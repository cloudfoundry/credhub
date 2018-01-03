package org.cloudfoundry.credhub.integration;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.TestConstants;
import org.hamcrest.Matchers;
import org.json.JSONObject;
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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.credhub.helper.RequestHelper.expect404WhileGeneratingCertificate;
import static org.cloudfoundry.credhub.helper.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helper.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CertificateGenerateTest {
  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  private static final String CREDENTIAL_NAME = "some-certificate";
  private static final String CA_NAME = "some-ca";
  private static final String CA_NAME2 = "some-ca2";

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void certificateGeneration_shouldGenerateCorrectCertificate() throws Exception {
    MockHttpServletRequestBuilder caPost = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"picard\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"is_ca\" : true,\n"
            + "    \"self_sign\" : true\n"
            + "  }\n"
            + "}");

    String caResult = this.mockMvc.perform(caPost)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    String picardCert = (new JSONObject(caResult)).getJSONObject("value").getString("certificate");
    String picardCA = (new JSONObject(caResult)).getJSONObject("value").getString("ca");
    assertThat(picardCert, equalTo(picardCA));

    assertThat(picardCert, notNullValue());

    MockHttpServletRequestBuilder certPost = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"riker\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"ca\" : \"picard\"\n"
            + "  }\n"
            + "}");

    String certResult = this.mockMvc.perform(certPost)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    String certCa = (new JSONObject(certResult)).getJSONObject("value").getString("ca");
    String cert = (new JSONObject(certResult)).getJSONObject("value").getString("certificate");

    assertThat(certCa, equalTo(picardCert));

    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate caPem = (X509Certificate) certificateFactory
        .generateCertificate(new ByteArrayInputStream(picardCert.getBytes()));

    X509Certificate certPem = (X509Certificate) certificateFactory
        .generateCertificate(new ByteArrayInputStream(cert.getBytes()));

    byte[] subjectKeyIdDer = caPem.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(subjectKeyIdDer));
    byte[] subjectKeyId = subjectKeyIdentifier.getKeyIdentifier();

    byte[] authorityKeyIdDer = certPem.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(authorityKeyIdDer));
    byte[] authKeyId = authorityKeyIdentifier.getKeyIdentifier();

    assertThat(subjectKeyId, equalTo(authKeyId));
  }

  @Test
  public void certificateGeneration_whenUserNotAuthorizedToReadCa_shouldReturnCorrectError() throws Exception {
    generateCa(mockMvc, "picard", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    // try to generate with a different token that doesn't have read permission
    expect404WhileGeneratingCertificate(mockMvc, "riker", UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN,
        "The request could not be completed because the credential does not exist or you do not have sufficient authorization.");
  }

  @Test
  public void invalidCertificateGenerationParameters_shouldResultInCorrectErrorMessage() throws Exception {
    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"picard\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789\",\n"
            + "    \"self_sign\" : true\n"
            + "  }\n"
            + "}");
    String error = "The request could not be completed because the common name is too long. The max length for common name is 64 characters.";

    this.mockMvc
        .perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo(error)));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSame() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, CredentialWriteMode.OVERWRITE.mode, "test-CA", null);

    String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME);
    String originalValue = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME);
    String sameValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, Matchers.equalTo(sameValue));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSameAndAreCAs() throws Exception {
    String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", null);
    String originalValue = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", null);
    String sameValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, Matchers.equalTo(sameValue));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndCommonNameNotTheSame() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, CredentialWriteMode.OVERWRITE.mode, "test-CA", null);

    String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME);
    String originalValue = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "other-common-name", CA_NAME);
    String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, not(Matchers.equalTo(updatedValue)));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetAndAllDNsSet() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, CredentialWriteMode.OVERWRITE.mode, "test-CA", null);

    Map<String, Object> certRequestBody = new HashMap() {
      {
        put("name", CREDENTIAL_NAME);
        put("type", "certificate");
        put("mode", CredentialWriteMode.CONVERGE.mode);
      }
    };

    Map parameters = new HashMap<String, Object>();
    parameters.put("ca", CA_NAME);
    parameters.put("common_name", "common_name");
    parameters.put("country", "US");
    parameters.put("locality", "Area 51");
    parameters.put("organization", "yes");


    certRequestBody.put("parameters", parameters);
    String content = JsonTestHelper.serializeToString(certRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    String firstResponse = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    String secondResponse = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();


    String originalValue = (new JSONObject(firstResponse)).getString("value");

    String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, equalTo(updatedValue));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndCaNameNotTheSame() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, CredentialWriteMode.OVERWRITE.mode, "test-CA", null);
    generateCertificateCredential(mockMvc, CA_NAME2, CredentialWriteMode.OVERWRITE.mode, "test-CA2", null);


    String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME);
    String originalValue = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME2);
    String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, not(Matchers.equalTo(updatedValue)));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndCAUpdated() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, CredentialWriteMode.OVERWRITE.mode, "test-CA", null);

    String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME);
    String originalValue = (new JSONObject(firstResponse)).getString("value");

    generateCertificateCredential(mockMvc, CA_NAME, CredentialWriteMode.OVERWRITE.mode, "test-CA", null);

    String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, "some-common-name", CA_NAME);
    String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, not(Matchers.equalTo(updatedValue)));
  }

  @Test
  public void certificateGeneratedReferencingACAWithoutAPrivateKeyReturnsBadRequest() throws Exception {
    final String setJson = net.minidev.json.JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("certificate", TestConstants.TEST_CA)
            .build());

    String caName = "crusher";
    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"" + caName + "\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().is2xxSuccessful());

    Map<String, Object> certRequestBody = new HashMap() {
      {
        put("name", CREDENTIAL_NAME);
        put("type", "certificate");
        put("mode", CredentialWriteMode.OVERWRITE.mode);
      }
    };

    Map parameters = new HashMap<String, Object>();
    parameters.put("ca", caName);
    parameters.put("common_name", "some-common-name");


    certRequestBody.put("parameters", parameters);
    String content = JsonTestHelper.serializeToString(certRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    this.mockMvc.perform(post)
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.error")
                .value("The specified CA object does not have an associated private key."));
  }

  @Test
  public void usesTheLatestNonTransitionalCaAsTheSigningCertificate() throws Exception {
    String generateCaResponse = generateCa(mockMvc, "/originalCA", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    String originalCaCertificate = JsonPath.parse(generateCaResponse)
        .read("$.value.certificate");
    String caId = JsonPath.parse(generateCaResponse)
        .read("$.id");

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "/originalCA");
    String uuid = JsonPath.parse(response)
        .read("$.certificates[0].id");

    MockHttpServletRequestBuilder caRegenerateRequest = post("/api/v1/certificates/" + uuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\"set_as_transitional\" : true}");

    String transitionalCaResponse = this.mockMvc.perform(caRegenerateRequest)
        .andExpect(status().is2xxSuccessful())
        .andReturn().getResponse().getContentAsString();

    String transitionalCaCertificate = JsonPath.parse(transitionalCaResponse)
        .read("$.value.certificate");

    String generateCertificateResponse = generateCertificateCredential(
        mockMvc,
        "/some-cert",
        CredentialWriteMode.OVERWRITE.mode,
        "test",
        "/originalCA"
    );

    String actualCaCertificate = JsonPath.parse(generateCertificateResponse)
        .read("$.value.ca");

    assertThat(actualCaCertificate, not(equalTo(transitionalCaCertificate)));
    assertThat(actualCaCertificate, equalTo(originalCaCertificate));
  }
}
