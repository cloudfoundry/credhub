package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repository.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
// @Transactional isn't thread-safe, so we need to clean up manually
public class CredentialsControllerConcurrencySetTest {
  @Autowired
  private Flyway flyway;

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;

  @Autowired
  private Encryptor encryptor;

  @Autowired
  private EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  private final String credentialName = "/my-namespace/secretForSetTest/credential-name";
  private final String credentialValue = "credential-value";
  private MockMvc mockMvc;
  private List<EncryptionKeyCanary> canaries;

  @Before
  public void beforeEach() {
    canaries = encryptionKeyCanaryRepository.findAll();

    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @After
  public void afterEach() {
    flyway.clean();
    flyway.setTarget(MigrationVersion.LATEST);
    flyway.migrate();

    encryptionKeyCanaryRepository.save(canaries);
    encryptionKeyCanaryRepository.flush();
  }

  @Test
  public void settingDifferentCredentialsInParallel_setsTheCredentials() throws Exception {
    ResultActions[] responses = new ResultActions[2];

    Thread thread1 = new Thread("thread-1") {
      @Override
      public void run() {
        final MockHttpServletRequestBuilder putReq = put("/api/v1/data")
            .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"type\":\"value\","
                + "  \"name\":\""
                + credentialName + this.getName() + "\",  \"value\":\""
                + credentialValue + this.getName() + "\"}");

        try {
          responses[0] = mockMvc.perform(putReq);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    };
    Thread thread2 = new Thread("thread-2") {
      @Override
      public void run() {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"type\":\"value\","
                + "  \"name\":\""
                + credentialName + this.getName() + "\",  \"value\":\""
                + credentialValue + this.getName() + "\"}");

        try {
          responses[1] = mockMvc.perform(put);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    };

    thread1.start();
    thread2.start();
    thread1.join();
    thread2.join();

    final String thread1Value = credentialValue + "thread-1";
    final String thread2Value = credentialValue + "thread-2";

    responses[0].andExpect(jsonPath("$.value").value(thread1Value));
    responses[1].andExpect(jsonPath("$.value").value(thread2Value));
  }

  @Test
  public void whenAnotherThreadsWinsARaceToUpdateACredential_retriesAndReturnsTheValueWrittenByTheOtherThread() throws Exception {
    UUID uuid = UUID.randomUUID();

    ValueCredentialVersion valueCredential = new ValueCredentialVersion(credentialName);
    valueCredential.setEncryptor(encryptor);
    valueCredential.setValue(credentialValue);
    valueCredential.setUuid(uuid);

    doReturn(null)
        .doReturn(valueCredential)
        .when(credentialVersionDataService).findMostRecent(anyString());

    doThrow(new DataIntegrityViolationException("we already have one of those"))
        .when(credentialVersionDataService).save(any(CredentialVersion.class));

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "\"type\":\"value\","
            + "\"name\":\"" + credentialName + "\","
            + "\"value\":\"" + credentialValue
            + "\"}");

    mockMvc.perform(put)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.type").value("value"))
        .andExpect(jsonPath("$.value").value(credentialValue))
        .andExpect(jsonPath("$.id").value(uuid.toString()));

    verify(credentialVersionDataService).save(any(CredentialVersion.class));
  }
}
