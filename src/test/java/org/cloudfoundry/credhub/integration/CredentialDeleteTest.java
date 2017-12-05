package org.cloudfoundry.credhub.integration;


import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.helper.RequestHelper;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialDeleteTest {
  private static final String CREDENTIAL_NAME = "/my-namespace/subTree/credential-name";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private CredentialVersionDataService credentialVersionDataService;

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
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
    RequestHelper.generateCa(mockMvc, CREDENTIAL_NAME, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    MockHttpServletRequestBuilder request = delete("/api/v1/data?name=" + CREDENTIAL_NAME.toUpperCase())
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    mockMvc.perform(request)
        .andExpect(status().isNoContent());

    auditingHelper.verifyAuditing(
        AuditingOperationCode.CREDENTIAL_DELETE, CREDENTIAL_NAME.toUpperCase(), AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 204);
  }

  @Test
  public void delete_whenThereIsOneCredentialVersionWithTheSlashPrependedName_deletesTheCredential() throws Exception {
    RequestHelper.generateCa(mockMvc, "/some-ca", AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    MockHttpServletRequestBuilder request = delete("/api/v1/data?name=" + "some-ca")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    mockMvc.perform(request)
        .andExpect(status().isNoContent());

    auditingHelper.verifyAuditing(
        AuditingOperationCode.CREDENTIAL_DELETE, "/some-ca", AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 204);
  }

  @Test
  public void delete_whenThereAreMultipleCredentialVersionsWithTheName_deletesAllVersions() throws Exception {
    RequestHelper.generateCa(mockMvc, CREDENTIAL_NAME, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    RequestHelper.generateCa(mockMvc, CREDENTIAL_NAME, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    MockHttpServletRequestBuilder request = delete("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    mockMvc.perform(request)
        .andExpect(status().isNoContent());

    auditingHelper.verifyAuditing(
        AuditingOperationCode.CREDENTIAL_DELETE, CREDENTIAL_NAME, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 204);
  }
}
