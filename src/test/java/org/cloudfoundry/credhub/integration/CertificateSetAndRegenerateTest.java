package org.cloudfoundry.credhub.integration;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.helper.RequestHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.json.JSONArray;
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

import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateId;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.cloudfoundry.credhub.util.TestConstants.TEST_CA;
import static org.cloudfoundry.credhub.util.TestConstants.TEST_CERTIFICATE;
import static org.cloudfoundry.credhub.util.TestConstants.TEST_PRIVATE_KEY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CertificateSetAndRegenerateTest {
  private static final String CA_NAME = "/picard";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private AuditingHelper auditingHelper;

  private MockMvc mockMvc;
  private String caCertificate;
  private String caId;
  private String caCredentialUuid;
  private String testSignedCert;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    MockHttpServletRequestBuilder generateCaRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" :\"" + CA_NAME + "\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"is_ca\" : true,\n"
            + "    \"self_sign\" : true\n"
            + "  }\n"
            + "}");

    final String generateCaResponse = this.mockMvc
        .perform(generateCaRequest)
        .andExpect(status().isOk())
        .andReturn().getResponse()
        .getContentAsString();

    caCertificate = JsonPath.parse(generateCaResponse)
        .read("$.value.certificate");
    caId = JsonPath.parse(generateCaResponse).read("$.id");
    caCredentialUuid = getCertificateId(mockMvc, CA_NAME);
    assertNotNull(caCertificate);

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void certificateSet_withCaName_canBeRegeneratedWithSameCA() throws Exception {
    final String generatedCertificate = RequestHelper
        .generateCertificateCredential(mockMvc, "generatedCertificate", CredentialWriteMode.OVERWRITE.mode,
            "generated-cert", CA_NAME);
    String certificateValue = JsonPath.parse(generatedCertificate)
        .read("$.value.certificate");
    String privateKeyValue = JsonPath.parse(generatedCertificate)
        .read("$.value.private_key");

    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", CA_NAME)
            .put("certificate", certificateValue)
            .put("private_key", privateKeyValue)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.value.ca", equalTo(caCertificate)));

    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"/crusher\"," +
            "\"regenerate\":true" +
            "}");

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.value.ca", equalTo(caCertificate)));
  }

  @Test
  public void certificateRegenerate_withTransitionalSetToTrue_generatesANewTransitionalCertificate() throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"set_as_transitional\": true" +
            "}");

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.transitional", equalTo(true)));

    MockHttpServletRequestBuilder getRequest = get("/api/v1/data?name=" + CA_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    this.mockMvc.perform(getRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].transitional", equalTo(true)));
  }

  @Test
  public void certificateRegenerate_withTransitionalSetToTrue_failsIfThereIsAlreadyATransitionalCert()
      throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"set_as_transitional\": true" +
            "}");

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.transitional", equalTo(true)));

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("The maximum number of transitional versions for a given CA is 1."));
  }

  @Test
  public void certificateRegenerate_withoutBodyWorks() throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    this.mockMvc.perform(regenerateRequest).andExpect(status().isOk());
  }

  @Test
  public void certificateSetRequest_whenProvidedANonCertificateValue_returnsAValidationError() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "")
            .put("certificate", "This is definitely not a certificate. Or is it?")
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The provided certificate value is not a valid X509 certificate.")));
  }

  @Test
  public void certificateSetRequest_whenProvidedACertificateValueThatIsTooLong_returnsAValidationError()
      throws Exception {
    int repetitionCount = 7001 - TEST_CERTIFICATE.length();
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "")
            .put("certificate", TEST_CERTIFICATE + StringUtils.repeat("a", repetitionCount))
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo(
            "The provided certificate value is too long. Certificate lengths must be less than 7000 characters.")));
  }

  @Test
  public void certificateSetRequest_whenProvidedACAValueThatIsTooLong_returnsAValidationError() throws Exception {
    int repetitionCount = 7001 - TEST_CA.length();
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca", TEST_CA + StringUtils.repeat("a", repetitionCount))
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo(
            "The provided certificate value is too long. Certificate lengths must be less than 7000 characters.")));
  }

  @Test
  public void certificateSetRequest_whenProvidedCertificateWasNotSignedByNamedCA_returnsAValidationError()
      throws Exception {
    RequestHelper.generateCa(mockMvc, "otherCa", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    final String otherCaCertificate = RequestHelper
        .generateCertificateCredential(mockMvc, "otherCaCertificate", CredentialWriteMode.OVERWRITE.mode,
            "other-ca-cert", "otherCa");

    String otherCaCertificateValue = JsonPath.parse(otherCaCertificate)
        .read("$.value.certificate");

    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", CA_NAME)
            .put("certificate", otherCaCertificateValue)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error",
            equalTo("The provided certificate was not signed by the CA specified in the 'ca_name' property.")));
  }

  @Test
  public void certificateSetRequest_whenProvidedCertificateWasNotSignedByProvidedCA_returnsAValidationError()
      throws Exception {
    RequestHelper.generateCa(mockMvc, "otherCa", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    final String otherCaCertificate = RequestHelper
        .generateCertificateCredential(mockMvc, "otherCaCertificate", CredentialWriteMode.OVERWRITE.mode,
            "other-ca-cert", "otherCa");

    String otherCaCertificateValue = JsonPath.parse(otherCaCertificate)
        .read("$.value.certificate");

    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca", TEST_CA)
            .put("certificate", otherCaCertificateValue)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error",
            equalTo("The provided certificate was not signed by the CA specified in the 'ca' property.")));
  }

  @Test
  public void certificateSetRequest_whenProvidedCertificateWithNonMatchingPrivateKey_returnsAValidationError()
      throws Exception {
    final String originalCertificate = RequestHelper.generateCa(mockMvc, "otherCa", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    final String otherCaCertificate = RequestHelper
        .generateCertificateCredential(mockMvc, "otherCaCertificate", CredentialWriteMode.OVERWRITE.mode,
            "other-ca-cert", "otherCa");

    String originalPrivateKeyValue = JsonPath.parse(originalCertificate)
        .read("$.value.private_key");
    String otherCaCertificateValue = JsonPath.parse(otherCaCertificate)
        .read("$.value.certificate");

    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "otherCa")
            .put("certificate", otherCaCertificateValue)
            .put("private_key", originalPrivateKeyValue)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The provided certificate does not match the private key.")));
  }

  @Test
  public void certificateSetRequest_withoutTransitionalProvided_shouldGenerateAVersionWithTransitionalFalse() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca", TEST_CA)
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    String content = "{\"value\" : " + setJson + "}";
    MockHttpServletRequestBuilder certificateSetRequest = post("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.value.ca", equalTo(TEST_CA)))
        .andExpect(jsonPath("$.value.certificate", equalTo(TEST_CERTIFICATE)))
        .andExpect(jsonPath("$.value.private_key", equalTo(TEST_PRIVATE_KEY)))
        .andExpect(jsonPath("$.name", equalTo(CA_NAME)))
        .andExpect(jsonPath("$.transitional", equalTo(false)));

    auditingHelper.verifyAuditing(AuditingOperationCode.CREDENTIAL_UPDATE, CA_NAME, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/certificates/" + caCredentialUuid + "/versions", 200);

    MockHttpServletRequestBuilder versionsGetRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String versionsResponse = this.mockMvc.perform(versionsGetRequest)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    JSONArray versions = new JSONArray(versionsResponse);
    assertThat(versions.length(), equalTo(2));
  }

  @Test
  public void certificateSetRequest_withTransitionalTrue_shouldGenerateAVersionWithTransitionalTrue() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca", TEST_CA)
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = post("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"value\" : " + setJson + ", \"transitional\": true}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.transitional", equalTo(true)));
  }

  @Test
  public void certificateSetRequest_withTransitionalTrue_whenThereIsAlreadyATransitionalVersion_shouldReturnAnError() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca", TEST_CA)
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = post("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"value\" : " + setJson + ", \"transitional\": true}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isOk());
    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("The maximum number of transitional versions for a given CA is 1."));
  }

  @Test
  public void certificateSetRequest_withInvalidParams_shouldReturnBadRequest() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("certificate", "fake-certificate")
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = post("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isBadRequest());
  }
}
