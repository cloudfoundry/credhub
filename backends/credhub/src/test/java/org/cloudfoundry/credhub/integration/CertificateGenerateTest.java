package org.cloudfoundry.credhub.integration;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.hamcrest.Matchers;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_B_TOKEN;
import static org.cloudfoundry.credhub.helpers.RequestHelper.expect404WhileGeneratingCertificate;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateCredentialsByName;
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
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredhubTestApp.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@Transactional
public class CertificateGenerateTest {
  private static final String CREDENTIAL_NAME = "some-certificate";
  private static final String CA_NAME = "some-ca";
  private static final String CA_NAME2 = "some-ca2";
  @Autowired
  private WebApplicationContext webApplicationContext;
  private MockMvc mockMvc;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void certificateGeneration_shouldGenerateCorrectCertificate() throws Exception {
    final MockHttpServletRequestBuilder caPost = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 1 \n"
        + "  }\n"
        + "}");

    final String caResult = this.mockMvc.perform(caPost)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();


    final String picardCert = (new JSONObject(caResult)).getJSONObject("value").getString("certificate");
    final String picardCA = (new JSONObject(caResult)).getJSONObject("value").getString("ca");
    assertThat(picardCert, equalTo(picardCA));

    final String expiryDate = (new JSONObject(caResult)).getString("expiry_date");
    final String truncatedExpiryDate = expiryDate.substring(0, expiryDate.indexOf('T'));

    final Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.DATE, 1);
    final String expectedTime = calendar.getTime().toInstant().truncatedTo(ChronoUnit.SECONDS).toString();
    final String truncatedExpected = expectedTime.substring(0, expectedTime.indexOf('T'));


    assertThat(truncatedExpiryDate, equalTo(truncatedExpected));


    assertThat(picardCert, notNullValue());

    final MockHttpServletRequestBuilder certPost = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
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

    final String certResult = this.mockMvc.perform(certPost)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String certCa = (new JSONObject(certResult)).getJSONObject("value").getString("ca");
    final String cert = (new JSONObject(certResult)).getJSONObject("value").getString("certificate");

    assertThat(certCa, equalTo(picardCert));


    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final X509Certificate caPem = (X509Certificate) certificateFactory
      .generateCertificate(new ByteArrayInputStream(picardCert.getBytes(StringUtil.UTF_8)));

    final X509Certificate certPem = (X509Certificate) certificateFactory
      .generateCertificate(new ByteArrayInputStream(cert.getBytes(StringUtil.UTF_8)));

    final byte[] subjectKeyIdDer = caPem.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    final SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(subjectKeyIdDer));
    final byte[] subjectKeyId = subjectKeyIdentifier.getKeyIdentifier();

    final byte[] authorityKeyIdDer = certPem.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    final AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(authorityKeyIdDer));
    final byte[] authKeyId = authorityKeyIdentifier.getKeyIdentifier();

    assertThat(subjectKeyId, equalTo(authKeyId));
  }

  @Test
  public void certificateGeneration_whenUserNotAuthorizedToReadCa_shouldReturnCorrectError() throws Exception {
    generateCa(mockMvc, "picard", ALL_PERMISSIONS_TOKEN);
    // try to generate with a different token that doesn't have read permission
    expect404WhileGeneratingCertificate(mockMvc, "riker", USER_B_TOKEN,
      "The request could not be completed because the credential does not exist or you do not have sufficient authorization.");
  }

  @Test
  public void invalidCertificateGenerationParameters_shouldResultInCorrectErrorMessage() throws Exception {
    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
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
    final String error = "The request could not be completed because the common name is too long. The max length for common name is 64 characters.";

    this.mockMvc
      .perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(error)));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSame() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, true, "test-CA", null, ALL_PERMISSIONS_TOKEN);

    final String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String originalValue = (new JSONObject(firstResponse)).getString("value");

    final String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String sameValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, Matchers.equalTo(sameValue));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSameAndAreCAs() throws Exception {
    final String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", null, ALL_PERMISSIONS_TOKEN);
    final String originalValue = (new JSONObject(firstResponse)).getString("value");

    final String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", null, ALL_PERMISSIONS_TOKEN);
    final String sameValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, Matchers.equalTo(sameValue));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndCommonNameNotTheSame() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, true, "test-CA", null, ALL_PERMISSIONS_TOKEN);

    final String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String originalValue = (new JSONObject(firstResponse)).getString("value");

    final String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "other-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, not(Matchers.equalTo(updatedValue)));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetAndAllDNsSet() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, true, "test-CA", null, ALL_PERMISSIONS_TOKEN);

    final Map<String, Object> certRequestBody = new HashMap() {
      {
        put("name", CREDENTIAL_NAME);
        put("type", "certificate");
      }
    };

    final Map parameters = new HashMap<String, Object>();
    parameters.put("ca", CA_NAME);
    parameters.put("common_name", "common_name");
    parameters.put("country", "US");
    parameters.put("locality", "Area 51");
    parameters.put("organization", "yes");


    certRequestBody.put("parameters", parameters);
    final String content = JsonTestHelper.serializeToString(certRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String firstResponse = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String secondResponse = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();


    final String originalValue = (new JSONObject(firstResponse)).getString("value");

    final String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, equalTo(updatedValue));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndCaNameNotTheSame() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, true, "test-CA", null, ALL_PERMISSIONS_TOKEN);
    generateCertificateCredential(mockMvc, CA_NAME2, true, "test-CA2", null, ALL_PERMISSIONS_TOKEN);


    final String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String originalValue = (new JSONObject(firstResponse)).getString("value");

    final String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME2, ALL_PERMISSIONS_TOKEN);
    final String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, not(Matchers.equalTo(updatedValue)));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndCAUpdated() throws Exception {
    generateCertificateCredential(mockMvc, CA_NAME, true, "test-CA", null, ALL_PERMISSIONS_TOKEN);

    final String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String originalValue = (new JSONObject(firstResponse)).getString("value");

    generateCertificateCredential(mockMvc, CA_NAME, true, "test-CA", null, ALL_PERMISSIONS_TOKEN);

    final String secondResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    final String updatedValue = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalValue, not(Matchers.equalTo(updatedValue)));
  }

  @Test
  public void certificateGeneratedReferencingACAWithoutAPrivateKeyReturnsBadRequest() throws Exception {
    final String setJson = net.minidev.json.JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("certificate", TestConstants.TEST_CA)
        .build());

    final String caName = "crusher";
    final MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"" + caName + "\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
      .andExpect(status().is2xxSuccessful());

    final Map<String, Object> certRequestBody = new HashMap() {
      {
        put("name", CREDENTIAL_NAME);
        put("type", "certificate");
        put("overwrite", true);
      }
    };

    final Map parameters = new HashMap<String, Object>();
    parameters.put("ca", caName);
    parameters.put("common_name", "some-common-name");


    certRequestBody.put("parameters", parameters);
    final String content = JsonTestHelper.serializeToString(certRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
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
    final String generateCaResponse = generateCa(mockMvc, "/originalCA", ALL_PERMISSIONS_TOKEN);
    final String originalCaCertificate = JsonPath.parse(generateCaResponse)
      .read("$.value.certificate");

    final String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, "/originalCA");
    final String uuid = JsonPath.parse(response)
      .read("$.certificates[0].id");

    final MockHttpServletRequestBuilder caRegenerateRequest = post("/api/v1/certificates/" + uuid + "/regenerate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\"set_as_transitional\" : true}");

    final String transitionalCaResponse = this.mockMvc.perform(caRegenerateRequest)
      .andExpect(status().is2xxSuccessful())
      .andReturn().getResponse().getContentAsString();

    final String transitionalCaCertificate = JsonPath.parse(transitionalCaResponse)
      .read("$.value.certificate");

    final String generateCertificateResponse = generateCertificateCredential(
      mockMvc,
      "/some-cert",
      true,
      "test",
      "/originalCA",
      ALL_PERMISSIONS_TOKEN
    );

    final String actualCaCertificate = JsonPath.parse(generateCertificateResponse)
      .read("$.value.ca");

    assertThat(actualCaCertificate, not(equalTo(transitionalCaCertificate)));
    assertThat(actualCaCertificate, equalTo(originalCaCertificate));
  }
}
