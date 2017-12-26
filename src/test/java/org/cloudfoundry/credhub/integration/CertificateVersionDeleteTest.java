package org.cloudfoundry.credhub.integration;


import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.helper.RequestHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.credhub.helper.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CertificateVersionDeleteTest {
  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;

  private AuditingHelper auditingHelper;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void deleteCertificateVersion_whenThereAreOtherVersionsOfTheCertificate_deletesTheSpecifiedVersion() throws Exception {
    String credentialName = "/test-certificate";

    String response = generateCertificateCredential(mockMvc, credentialName, CredentialWriteMode.OVERWRITE.mode, "test", null);
    String nonDeletedVersion = JsonPath.parse(response).read("$.value.certificate");

    response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, credentialName);
    String uuid = JsonPath.parse(response)
        .read("$.certificates[0].id");

    String version = RequestHelper.regenerateCertificate(mockMvc, uuid, false);
    String versionUuid = JsonPath.parse(version).read("$.id");
    String versionValue = JsonPath.parse(version).read("$.value.certificate");

    final MockHttpServletRequestBuilder request = delete("/api/v1/certificates/" + uuid + "/versions/" + versionUuid)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    auditingHelper.verifyAuditing(AuditingOperationCode.CREDENTIAL_DELETE, credentialName, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates/" + uuid + "/versions/" + versionUuid, 200);

    String certificate = JsonPath.parse(response)
        .read("$.value.certificate");
    assertThat(certificate, equalTo(versionValue));

    response = mockMvc.perform(get("/api/v1/certificates/" + uuid + "/versions")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)).andReturn().getResponse().getContentAsString();

    JSONArray jsonArray = new JSONArray(response);
    assertThat(jsonArray.length(), equalTo(1));
    assertThat(JsonPath.parse(jsonArray.get(0).toString()).read("$.value.certificate"), equalTo(nonDeletedVersion));
  }

  @Test
  public void deleteCertificateVersion_whenThereAreNoOtherVersionsOfTheCertificate_returnsAnError() throws Exception {
    String credentialName = "/test-certificate";

    String response = generateCertificateCredential(mockMvc, credentialName, CredentialWriteMode.OVERWRITE.mode, "test", null);
    String versionUuid = JsonPath.parse(response).read("$.id");

    response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, credentialName);
    String uuid = JsonPath.parse(response)
        .read("$.certificates[0].id");

    final MockHttpServletRequestBuilder request = delete("/api/v1/certificates/" + uuid + "/versions/" + versionUuid)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The minimum number of versions for a Certificate is 1.")));
    auditingHelper.verifyAuditing(AuditingOperationCode.CREDENTIAL_DELETE, credentialName, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates/" + uuid + "/versions/" + versionUuid, 400);
  }
}
