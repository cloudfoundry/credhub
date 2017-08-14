package io.pivotal.security.controller.v1.credential;


import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialsControllerDeleteTest {
  private static final String CREDENTIAL_NAME = "/my-namespace/subTree/credential-name";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialDataService credentialDataService;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void delete_whenNoCredentialExistsWithTheName_returnsAnError() throws Exception {
    final MockHttpServletRequestBuilder delete = delete("/api/v1/data?name=invalid_name")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(delete)
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void delete_whenNameIsEmpty_returnAnError() throws Exception {
    final MockHttpServletRequestBuilder delete = delete("/api/v1/data?name=")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(delete)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(
            jsonPath("$.error")
                .value("The query parameter name is required for this request.")
        );
  }

  @Test
  public void delete_whenNameIsMissing_returnAnError() throws Exception {
    final MockHttpServletRequestBuilder delete = delete("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(delete)
        .andExpect(status().is4xxClientError())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(
            jsonPath("$.error")
                .value("The query parameter name is required for this request.")
        );
  }

  @Test
  public void delete_whenThereIsOneCredentialVersionWithTheCaseInsensitiveName_deletesTheCredential() throws Exception {
    doReturn(true).when(credentialDataService).delete(CREDENTIAL_NAME.toUpperCase());
    doReturn(new ValueCredential())
        .when(credentialDataService)
        .findMostRecent(CREDENTIAL_NAME.toUpperCase());

    MockHttpServletRequestBuilder request = delete("/api/v1/data?name=" + CREDENTIAL_NAME.toUpperCase())
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    mockMvc.perform(request)
        .andExpect(status().isNoContent());

    verify(credentialDataService, times(1)).delete(CREDENTIAL_NAME.toUpperCase());

    auditingHelper.verifyAuditing(CREDENTIAL_DELETE, CREDENTIAL_NAME.toUpperCase(), "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 204);
  }

  @Test
  public void delete_whenThereAreMultipleCredentialVersionsWithTheName_deletesAllVersions() throws Exception {
    doReturn(true).when(credentialDataService).delete(CREDENTIAL_NAME);
    doReturn(new ValueCredential()).when(credentialDataService).findMostRecent(CREDENTIAL_NAME);

    MockHttpServletRequestBuilder request = delete("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    mockMvc.perform(request)
        .andExpect(status().isNoContent());

    verify(credentialDataService, times(1)).delete(CREDENTIAL_NAME);

    auditingHelper.verifyAuditing(CREDENTIAL_DELETE, CREDENTIAL_NAME, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 204);
  }
}
