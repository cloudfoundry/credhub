package org.cloudfoundry.credhub.integration;


import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredentialManagerApp;
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

import java.util.List;
import java.util.Map;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static org.cloudfoundry.credhub.helper.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helper.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helper.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentials;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CertificateGetTest {
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
  public void getCertificateCredentials_returnsAllCertificateCredentials() throws Exception {
    generateCertificateCredential(mockMvc, "/first-certificate", CredentialWriteMode.OVERWRITE.mode, "test", null);
    generateCertificateCredential(mockMvc, "/second-certificate", CredentialWriteMode.OVERWRITE.mode, "first-version", null);
    generateCertificateCredential(mockMvc, "/second-certificate", CredentialWriteMode.OVERWRITE.mode, "second-version", null);
    generatePassword(mockMvc, "invalid-cert", CredentialWriteMode.OVERWRITE.mode, null);
    String response = getCertificateCredentials(mockMvc);

    List<String> names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(2));
    assertThat(names, containsInAnyOrder("/first-certificate", "/second-certificate"));
    assertThat(names, not(containsInAnyOrder("/invalid-cert")));

    auditingHelper.verifyAuditing(CREDENTIAL_FIND, null, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 200);
  }

  @Test
  public void getCertificateCredentials_returnsOnlyCertificatesTheUserCanAccess() throws Exception {
    generateCa(mockMvc, "my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    generateCa(mockMvc, "your-certificate", UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);

    String response = getCertificateCredentials(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    List<String> names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, containsInAnyOrder("/my-certificate"));
    assertThat(names, not(containsInAnyOrder("/your-certificate")));

    response = getCertificateCredentials(mockMvc, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, not(containsInAnyOrder("/my-certificate")));
    assertThat(names, containsInAnyOrder("/your-certificate"));
  }

  @Test
  public void getCertificateCredentials_withNameProvided_returnsACertificateWithThatName() throws Exception {
    generateCa(mockMvc, "my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    generateCa(mockMvc, "also-my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "my-certificate");
    List<String> names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, containsInAnyOrder("/my-certificate"));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/my-certificate", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 200);
  }

  @Test
  public void getCertificateCredentials_whenNameDoesNotMatchACredential_returns404WithMessage() throws Exception {
    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "some-other-certificate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/some-other-certificate", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 404);
  }

  @Test
  public void getCertificateCredentialsByName_doesNotReturnOtherCredentialTypes() throws Exception {
    generatePassword(mockMvc, "my-credential", CredentialWriteMode.OVERWRITE.mode, 10);

    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "my-credential")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/my-credential", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 404);
  }

  @Test
  public void getCertificateCredentials_whenNameIsProvided_andUserDoesNotHaveRequiredPermissions_returns404WithMessage() throws Exception {
    generateCa(mockMvc, "my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "my-certificate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/my-certificate", UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID, "/api/v1/certificates", 404);
  }

  @Test
  public void getCertificateVersionsByCredentialId_returnsAllVersionsOfTheCertificateCredential() throws Exception {
    String firstResponse = generateCertificateCredential(mockMvc, "/first-certificate", CredentialWriteMode.OVERWRITE.mode, "test", null);
    String secondResponse = generateCertificateCredential(mockMvc, "/first-certificate", CredentialWriteMode.OVERWRITE.mode, "test", null);

    String firstVersion = JsonPath.parse(firstResponse).read("$.id");
    String secondVersion = JsonPath.parse(secondResponse).read("$.id");

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "/first-certificate");

    String certificateId  = JsonPath.parse(response).read("$.certificates[0].id");

    MockHttpServletRequestBuilder getVersions = get("/api/v1/certificates/" + certificateId + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String responseVersion = mockMvc.perform(getVersions)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    List<Map<String, String>> certificates = JsonPath.parse(responseVersion).read("$");

    assertThat(certificates, hasSize(2));
    assertThat(certificates.get(0).get("id"), containsString(secondVersion));
    assertThat(certificates.get(1).get("id"), containsString(firstVersion));

    auditingHelper.verifyAuditing(CREDENTIAL_ACCESS, "/first-certificate", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates/"+ certificateId+ "/versions", 200);

  }

  @Test
  public void getCertificateVersionsByCredentialId_withCurrentTrue_returnsCurrentVersionsOfTheCertificateCredential() throws Exception {
    String credentialName = "/test-certificate";

    generateCertificateCredential(mockMvc, credentialName, CredentialWriteMode.OVERWRITE.mode, "test", null);

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, credentialName);
    String uuid = JsonPath.parse(response)
        .read("$.certificates[0].id");

    String transitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, true))
        .read("$.value.certificate");

    String nonTransitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, false))
        .read("$.value.certificate");

    final MockHttpServletRequestBuilder request = get("/api/v1/certificates/" + uuid + "/versions?current=true")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    JSONArray jsonArray = new JSONArray(response);

    assertThat(jsonArray.length(), equalTo(2));
    List<String> certificates = JsonPath.parse(response)
        .read("$[*].value.certificate");
    assertThat(certificates, containsInAnyOrder(transitionalCertificate, nonTransitionalCertificate));
  }

  @Test
  public void getCertificateVersionsByCredentialId_returnsError_whenUUIDIsInvalid() throws Exception {

    MockHttpServletRequestBuilder get = get("/api/v1/certificates/" + "fake-uuid" + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().is4xxClientError())
        .andReturn().getResponse().getContentAsString();

      assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
      auditingHelper.verifyAuditing(CREDENTIAL_ACCESS, null, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates/fake-uuid/versions", 404);
  }
}
