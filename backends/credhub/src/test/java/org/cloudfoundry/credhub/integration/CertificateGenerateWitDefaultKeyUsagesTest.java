package org.cloudfoundry.credhub.integration;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Calendar;

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

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
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
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
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
@TestPropertySource(properties = "certificates.enable_default_ca_key_usages=true")
@Transactional
public class CertificateGenerateWitDefaultKeyUsagesTest {

  @Autowired
  private WebApplicationContext webApplicationContext;
  private MockMvc mockMvc;

  @Rule
  public Timeout globalTimeout = Timeout.seconds(60);

  @BeforeClass
  public static void beforeAll() {
    BouncyCastleFipsConfigurer.configure();
  }

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
                    + "    \"duration\" : 1 \n"
                    + "  }\n"
                    + "}");

    final String caResult = mockMvc.perform(caPost)
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

    JSONObject result = new JSONObject(caResult);
    final String picardCert = result.getJSONObject("value").getString("certificate");
    final String picardCA = result.getJSONObject("value").getString("ca");
    assertThat(picardCert, equalTo(picardCA));

    final String expiryDate = result.getString("expiry_date");
    final String truncatedExpiryDate = expiryDate.substring(0, expiryDate.indexOf('T'));

    final Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.DATE, 1);
    final String expectedTime = calendar.getTime().toInstant().truncatedTo(ChronoUnit.SECONDS).toString();
    final String truncatedExpected = expectedTime.substring(0, expectedTime.indexOf('T'));


    assertThat(truncatedExpiryDate, equalTo(truncatedExpected));
    assertThat(result.getBoolean("certificate_authority"), equalTo(true));
    assertThat(result.getBoolean("self_signed"), equalTo(true));
    assertThat(result.getBoolean("generated"), equalTo(true));
    assertThat(result.getBoolean("duration_overridden"), equalTo(false));
    assertThat(result.getInt("duration_used"), equalTo(1));

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

    final String certResult = mockMvc.perform(certPost)
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

    final String certCa = (new JSONObject(certResult)).getJSONObject("value").getString("ca");
    final String cert = (new JSONObject(certResult)).getJSONObject("value").getString("certificate");

    assertThat(certCa, equalTo(picardCert));


    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final X509Certificate caPem = (X509Certificate) certificateFactory
            .generateCertificate(new ByteArrayInputStream(picardCert.getBytes(UTF_8)));

    final X509Certificate certPem = (X509Certificate) certificateFactory
            .generateCertificate(new ByteArrayInputStream(cert.getBytes(UTF_8)));

    final byte[] subjectKeyIdDer = caPem.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    final SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(subjectKeyIdDer));
    final byte[] subjectKeyId = subjectKeyIdentifier.getKeyIdentifier();

    final byte[] authorityKeyIdDer = certPem.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    final AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(authorityKeyIdDer));
    final byte[] authKeyId = authorityKeyIdentifier.getKeyIdentifier();

    assertThat(subjectKeyId, equalTo(authKeyId));

    final byte[] generatedKeyUsageCA = caPem.getExtensionValue(Extension.keyUsage.getId());
    assertThat(generatedKeyUsageCA, notNullValue());
    assertThat(Arrays.copyOfRange(generatedKeyUsageCA, 5, generatedKeyUsageCA.length), equalTo(new KeyUsage(keyCertSign | cRLSign).getBytes()));

    final byte[] generatedKeyUsageCert = certPem.getExtensionValue(Extension.keyUsage.getId());
    assertThat(generatedKeyUsageCert, nullValue());
  }

}
