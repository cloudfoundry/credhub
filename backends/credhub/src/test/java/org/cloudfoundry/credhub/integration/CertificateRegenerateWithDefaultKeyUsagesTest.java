package org.cloudfoundry.credhub.integration;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
import static org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateId;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for verifying default CA key usage behavior during certificate generation
 * and regeneration.
 *
 * This test class contains two nested test classes that verify behavior with the feature
 * flag both DISABLED and ENABLED:
 *
 * 1. CertificateGenerateWithDefaultKeyUsagesDisabledTest: Tests behavior when certificates.enable_default_ca_key_usages=false
 *    - CAs should NOT have default key usages
 *    - Regeneration should preserve the absence of key usages
 *
 * 2. CertificateGenerateWithDefaultKeyUsagesEnabledTest: Tests behavior when certificates.enable_default_ca_key_usages=true
 *    - CAs should have default key usages (keyCertSign | cRLSign)
 *    - Regeneration should maintain default key usages
 *    - Explicit key usages should be preserved
 *
 * Together, these nested classes simulate the real-world deployment scenario:
 * Phase 1 (Disabled): Old deployment - CAs created without key usages
 * Phase 2 (Enabled): New deployment - CAs get/maintain key usages on generation/regeneration
 *
 */
public final class CertificateRegenerateWithDefaultKeyUsagesTest {

  private CertificateRegenerateWithDefaultKeyUsagesTest() {
    // Utility class - private constructor to prevent instantiation
  }

  @BeforeClass
  public static void beforeAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @RunWith(SpringRunner.class)
  @ActiveProfiles(
          value = {
                  "unit-test",
                  "unit-test-permissions",
          },
          resolver = DatabaseProfileResolver.class
  )
  @SpringBootTest(classes = CredhubTestApp.class)
  @TestPropertySource(properties = "certificates.enable_default_ca_key_usages=false")
  @Transactional
  public static class CertificateGenerateWithDefaultKeyUsagesDisabledTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @Rule
    public Timeout globalTimeout = Timeout.seconds(60);

    @Before
    public void beforeEach() throws Exception {
      mockMvc = MockMvcBuilders
              .webAppContextSetup(webApplicationContext)
              .apply(springSecurity())
              .build();
    }

    @Test
    public void certificateRegeneration_shouldNotApplyDefaultKeyUsages() throws Exception {
      final MockHttpServletRequestBuilder caPost = post("/api/v1/data")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"name\" : \"test-ca-no-key-usage\",\n"
                      + "  \"type\" : \"certificate\",\n"
                      + "  \"parameters\" : {\n"
                      + "    \"common_name\" : \"test-ca-regenerate\",\n"
                      + "    \"is_ca\" : true,\n"
                      + "    \"duration\" : 365\n"
                      + "  }\n"
                      + "}");

      final String caResult = mockMvc.perform(caPost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject caResultJson = new JSONObject(caResult);
      final String originalCaCert = caResultJson.getJSONObject("value").getString("certificate");

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final X509Certificate originalCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(originalCaCert.getBytes(UTF_8)));

      final byte[] originalCaKeyUsageDer = originalCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Original CA should not have key usage extension when feature is disabled",
              originalCaKeyUsageDer, nullValue());

      final String certificateId = getCertificateId(mockMvc, "test-ca-no-key-usage");

      final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/certificates/" + certificateId + "/regenerate")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"key_length\": 3072\n"
                      + "}");

      final String regenerateResult = mockMvc.perform(regeneratePost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject regenerateResultJson = new JSONObject(regenerateResult);
      final String regeneratedCaCert = regenerateResultJson.getJSONObject("value").getString("certificate");

      final X509Certificate regeneratedCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(regeneratedCaCert.getBytes(UTF_8)));

      final byte[] regeneratedCaKeyUsageDer = regeneratedCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Regenerated CA should still not have key usage extension when feature remains disabled",
              regeneratedCaKeyUsageDer, nullValue());
    }
  }

  @RunWith(SpringRunner.class)
  @ActiveProfiles(
          value = {
                  "unit-test",
                  "unit-test-permissions",
          },
          resolver = DatabaseProfileResolver.class
  )
  @SpringBootTest(classes = CredhubTestApp.class)
  @TestPropertySource(properties = "certificates.enable_default_ca_key_usages=true")
  @Transactional
  public static class CertificateGenerateWithDefaultKeyUsagesEnabledTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @Rule
    public Timeout globalTimeout = Timeout.seconds(60);

    @Before
    public void beforeEach() throws Exception {
      mockMvc = MockMvcBuilders
              .webAppContextSetup(webApplicationContext)
              .apply(springSecurity())
              .build();
    }

    @Test
    public void certificateGeneration_shouldApplyDefaultKeyUsages() throws Exception {
      final MockHttpServletRequestBuilder caPost = post("/api/v1/data")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"name\" : \"test-ca-with-default-key-usage\",\n"
                      + "  \"type\" : \"certificate\",\n"
                      + "  \"parameters\" : {\n"
                      + "    \"common_name\" : \"test-ca-with-key-usage\",\n"
                      + "    \"is_ca\" : true,\n"
                      + "    \"duration\" : 365\n"
                      + "  }\n"
                      + "}");

      final String caResult = mockMvc.perform(caPost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject caResultJson = new JSONObject(caResult);
      final String caCert = caResultJson.getJSONObject("value").getString("certificate");

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final X509Certificate caCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(caCert.getBytes(UTF_8)));

      final byte[] caKeyUsageDer = caCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("CA should have key usage extension when feature is enabled",
              caKeyUsageDer, notNullValue());
      assertThat("CA should have default CA key usages (keyCertSign | cRLSign)",
              Arrays.copyOfRange(caKeyUsageDer, 5, caKeyUsageDer.length),
              equalTo(new KeyUsage(keyCertSign | cRLSign).getBytes()));
    }

    @Test
    public void certificateRegeneration_shouldMaintainDefaultKeyUsages() throws Exception {
      // Generate a CA with default key usages
      final MockHttpServletRequestBuilder caPost = post("/api/v1/data")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"name\" : \"test-ca-regenerate-with-key-usage\",\n"
                      + "  \"type\" : \"certificate\",\n"
                      + "  \"parameters\" : {\n"
                      + "    \"common_name\" : \"test-ca-regenerate-with-key-usage\",\n"
                      + "    \"is_ca\" : true,\n"
                      + "    \"duration\" : 365\n"
                      + "  }\n"
                      + "}");

      final String caResult = mockMvc.perform(caPost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject caResultJson = new JSONObject(caResult);
      final String originalCaCert = caResultJson.getJSONObject("value").getString("certificate");

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final X509Certificate originalCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(originalCaCert.getBytes(UTF_8)));

      final byte[] originalCaKeyUsageDer = originalCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Original CA should have key usage extension when feature is enabled",
              originalCaKeyUsageDer, notNullValue());

      // Regenerate the CA
      final String certificateId = getCertificateId(mockMvc, "test-ca-regenerate-with-key-usage");

      final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/certificates/" + certificateId + "/regenerate")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"key_length\": 3072\n"
                      + "}");

      final String regenerateResult = mockMvc.perform(regeneratePost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject regenerateResultJson = new JSONObject(regenerateResult);
      final String regeneratedCaCert = regenerateResultJson.getJSONObject("value").getString("certificate");

      final X509Certificate regeneratedCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(regeneratedCaCert.getBytes(UTF_8)));

      final byte[] regeneratedCaKeyUsageDer = regeneratedCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Regenerated CA should maintain key usage extension",
              regeneratedCaKeyUsageDer, notNullValue());
      assertThat("Regenerated CA should maintain default CA key usages (keyCertSign | cRLSign)",
              Arrays.copyOfRange(regeneratedCaKeyUsageDer, 5, regeneratedCaKeyUsageDer.length),
              equalTo(new KeyUsage(keyCertSign | cRLSign).getBytes()));
    }

    @Test
    public void certificateRegeneration_shouldApplyDefaultKeyUsagesToCaCreatedWithoutThem() throws Exception {

      final String setJson = new ObjectMapper().writeValueAsString(
              ImmutableMap.<String, String>builder()
                      .put("certificate", TestConstants.TEST_CA)
                      .build());

      final MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              //language=JSON
              .content("{\n"
                      + "  \"name\" : \"test-ca-without-key-usages\",\n"
                      + "  \"type\" : \"certificate\",\n"
                      + "  \"value\" : " + setJson + "}");

      final String caResult = mockMvc.perform(certificateSetRequest)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject caResultJson = new JSONObject(caResult);
      final String originalCaCert = caResultJson.getJSONObject("value").getString("certificate");

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final X509Certificate originalCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(originalCaCert.getBytes(UTF_8)));

      final byte[] originalCaKeyUsageDer = originalCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Original CA (from TEST_CA constant) should not have key usage extension",
              originalCaKeyUsageDer, nullValue());

      final String certificateId = getCertificateId(mockMvc, "test-ca-without-key-usages");

      final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/certificates/" + certificateId + "/regenerate")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"key_length\": 3072\n"
                      + "}");

      final String regenerateResult = mockMvc.perform(regeneratePost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject regenerateResultJson = new JSONObject(regenerateResult);
      final String regeneratedCaCert = regenerateResultJson.getJSONObject("value").getString("certificate");

      final X509Certificate regeneratedCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(regeneratedCaCert.getBytes(UTF_8)));

      final byte[] regeneratedCaKeyUsageDer = regeneratedCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Regenerated CA should now have key usage extension (feature applies default key usages)",
              regeneratedCaKeyUsageDer, notNullValue());
      assertThat("Regenerated CA should have default CA key usages (keyCertSign | cRLSign)",
              Arrays.copyOfRange(regeneratedCaKeyUsageDer, 5, regeneratedCaKeyUsageDer.length),
              equalTo(new KeyUsage(keyCertSign | cRLSign).getBytes()));
    }

    @Test
    public void certificateRegeneration_withExplicitKeyUsages_shouldPreserveThem() throws Exception {
      // Generate a CA with explicit non-default key usages
      final MockHttpServletRequestBuilder caPost = post("/api/v1/data")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"name\" : \"test-ca-explicit-key-usage\",\n"
                      + "  \"type\" : \"certificate\",\n"
                      + "  \"parameters\" : {\n"
                      + "    \"common_name\" : \"test-ca-explicit\",\n"
                      + "    \"is_ca\" : true,\n"
                      + "    \"duration\" : 365,\n"
                      + "    \"key_usage\" : [\"digital_signature\", \"key_cert_sign\"]\n"
                      + "  }\n"
                      + "}");

      final String caResult = mockMvc.perform(caPost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject caResultJson = new JSONObject(caResult);
      final String originalCaCert = caResultJson.getJSONObject("value").getString("certificate");

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final X509Certificate originalCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(originalCaCert.getBytes(UTF_8)));

      final byte[] originalCaKeyUsageDer = originalCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Original CA should have explicit key usage extension",
              originalCaKeyUsageDer, notNullValue());

      final byte[] originalKeyUsageBytes = Arrays.copyOfRange(originalCaKeyUsageDer, 5, originalCaKeyUsageDer.length);

      // Regenerate the CA
      final String certificateId = getCertificateId(mockMvc, "test-ca-explicit-key-usage");

      final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/certificates/" + certificateId + "/regenerate")
              .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                      + "  \"key_length\": 3072\n"
                      + "}");

      final String regenerateResult = mockMvc.perform(regeneratePost)
              .andDo(print())
              .andExpect(status().isOk())
              .andReturn().getResponse().getContentAsString();

      final JSONObject regenerateResultJson = new JSONObject(regenerateResult);
      final String regeneratedCaCert = regenerateResultJson.getJSONObject("value").getString("certificate");

      final X509Certificate regeneratedCaCertPem = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(regeneratedCaCert.getBytes(UTF_8)));

      final byte[] regeneratedCaKeyUsageDer = regeneratedCaCertPem.getExtensionValue(Extension.keyUsage.getId());
      assertThat("Regenerated CA should preserve explicit key usage extension",
              regeneratedCaKeyUsageDer, notNullValue());

      final byte[] regeneratedKeyUsageBytes = Arrays.copyOfRange(regeneratedCaKeyUsageDer, 5, regeneratedCaKeyUsageDer.length);
      assertThat("Regenerated CA should preserve the original explicit key usages",
              regeneratedKeyUsageBytes, equalTo(originalKeyUsageBytes));
    }
  }
}

