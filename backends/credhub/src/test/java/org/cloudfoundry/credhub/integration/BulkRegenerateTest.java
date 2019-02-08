package org.cloudfoundry.credhub.integration;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateId;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
public class BulkRegenerateTest {
  private static final String API_V1_DATA_ENDPOINT = "/api/v1/data";
  private static final String API_V1_BULK_REGENERATE_ENDPOINT = "/api/v1/bulk-regenerate";
  private static final String API_V1_PERMISSION_ENDPOINT = "/api/v1/permissions";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private CredentialVersionDataService credentialVersionDataService;

  @Autowired
  private CredentialVersionRepository credentialVersionRepository;

  private MockMvc mockMvc;
  private String caName;
  private String cert1Name;
  private String cert2Name;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    caName = randomCredentialName("ca-to-rotate");
    cert1Name = randomCredentialName("cert-1");
    cert2Name = randomCredentialName("cert-2");
    final String otherCAName = randomCredentialName("other-ca");
    final String otherCertName = randomCredentialName("other-cert");

    generateRootCA(caName);
    generateRootCA(otherCAName);
    generateSignedCertificate(cert1Name, caName);
    generateSignedCertificate(cert2Name, caName);
    generateSignedCertificate(otherCertName, otherCAName);

    grantPermissions(caName, USER_A_ACTOR_ID, "read");
    grantPermissions(otherCAName, USER_A_ACTOR_ID, "read");
    grantPermissions(cert1Name, USER_A_ACTOR_ID, "read", "write");
    grantPermissions(cert2Name, USER_A_ACTOR_ID, "read", "write");
    grantPermissions(otherCertName, USER_A_ACTOR_ID, "read", "write");
  }

  @After
  public void afterEach() {
    credentialVersionRepository.deleteAllInBatch();
  }

  @Test
  public void regeneratingCertificatesSignedByCA_shouldRegenerateCertificates() throws Exception {
    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\"signed_by\" : \"" + caName + "\"}");

    final String regenerateCertificatesResult = this.mockMvc.perform(regenerateCertificatesRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final JSONArray regeneratedCredentials = (new JSONObject(regenerateCertificatesResult)).getJSONArray("regenerated_credentials");
    final List<String> result = Arrays.asList(regeneratedCredentials.getString(0), regeneratedCredentials.getString(1));

    assertThat(regeneratedCredentials.length(), equalTo(2));
    assertThat(result, containsInAnyOrder(cert1Name, cert2Name));
  }

  @Test
  public void regeneratingCertificatesSignedByCA_shouldRegenerateCertificatesInAlphabeticalOrder() throws Exception {
    final String firstAlphabeticalCertName = randomCredentialName("aa-cert");
    generateSignedCertificate(firstAlphabeticalCertName, caName);
    grantPermissions(firstAlphabeticalCertName, USER_A_ACTOR_ID, "read", "write");

    final String lastAlphabeticalCertName = randomCredentialName("zz-cert");
    generateSignedCertificate(lastAlphabeticalCertName, caName);
    grantPermissions(lastAlphabeticalCertName, USER_A_ACTOR_ID, "read", "write");

    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\"signed_by\" : \"" + caName + "\"}");

    final String regenerateCertificatesResult = this.mockMvc.perform(regenerateCertificatesRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final JSONArray regeneratedCredentials = (new JSONObject(regenerateCertificatesResult)).getJSONArray("regenerated_credentials");
    final List<String> result = Arrays.asList(regeneratedCredentials.getString(0), regeneratedCredentials.getString(1), regeneratedCredentials.getString(2), regeneratedCredentials.getString(3));

    assertThat(regeneratedCredentials.length(), equalTo(4));
    assertThat(result.get(0), equalTo(firstAlphabeticalCertName));
    assertThat(result.get(1), equalTo(cert1Name));
    assertThat(result.get(2), equalTo(cert2Name));
    assertThat(result.get(3), equalTo(lastAlphabeticalCertName));
  }

  @Test
  public void regeneratingCertificatesSignedByCA_whenUserCannotWriteToOneOfTheCertificates_shouldFailAndNotRotateAnyCertificates() throws Exception {
    revokePermissions(cert1Name, USER_A_ACTOR_ID);

    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\"signed_by\" : \"" + caName + "\"}");

    mockMvc.perform(regenerateCertificatesRequest)
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("The request could not be completed because the credential does not exist or you do not have sufficient authorization.")));

    assertThat(credentialVersionDataService.findAllByName(cert1Name).size(), equalTo(1));
    assertThat(credentialVersionDataService.findAllByName(cert2Name).size(), equalTo(1));
  }

  @Test
  public void regeneratingCertificatesSignedByCA_whenUserCannotReadCa_shouldFailAndNotRotateAnyCertificates() throws Exception {
    revokePermissions(caName, USER_A_ACTOR_ID);

    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\"signed_by\" : \"" + caName + "\"}");

    mockMvc.perform(regenerateCertificatesRequest)
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo("The request could not be completed because the credential does not exist or you do not have sufficient authorization.")));

    assertThat(credentialVersionDataService.findAllByName(cert1Name).size(), equalTo(1));
    assertThat(credentialVersionDataService.findAllByName(cert2Name).size(), equalTo(1));
  }

  @Test
  public void regeneratingCertificatesSignedByCA_whenSignedByIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{}");

    mockMvc.perform(regenerateCertificatesRequest)
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("You must specify a signing CA. Please update and retry your request.")));
  }

  @Test
  public void regeneratingCertificatesSignedByCa_recursivelyRegeneratesLeafCertificatesInChain() throws Exception {
    final String intermediateCert = randomCredentialName("intermediate-cert");
    generateSignedCertificate(intermediateCert, caName, true);
    grantPermissions(intermediateCert, USER_A_ACTOR_ID, "read", "write");

    final String leafCert = randomCredentialName("leaf-cert");
    generateSignedCertificate(leafCert, intermediateCert);
    grantPermissions(leafCert, USER_A_ACTOR_ID, "read", "write");

    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\"signed_by\" : \"" + caName + "\"}");

    final String regenerateCertificatesResult = this.mockMvc.perform(regenerateCertificatesRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final List<String> regeneratedCredentials = JsonPath.parse(regenerateCertificatesResult).read("$.regenerated_credentials");
    assertThat(regeneratedCredentials.size(), equalTo(4));
    assertThat(regeneratedCredentials, containsInAnyOrder(cert1Name, cert2Name, intermediateCert, leafCert));

    verifyVersionCountForCertificate(intermediateCert, 2);
    verifyVersionCountForCertificate(leafCert, 2);
  }

  @Test
  public void regeneratingCertificatesSignedByCa_willFailIfAnyChildCertificateIsNotWritable() throws Exception {
    final String intermediateCert = randomCredentialName("intermediate-cert");
    generateSignedCertificate(intermediateCert, caName, true);
    grantPermissions(intermediateCert, USER_A_ACTOR_ID, "read", "write");

    final String leafCert = randomCredentialName("leaf-cert");
    generateSignedCertificate(leafCert, intermediateCert);
    grantPermissions(leafCert, USER_A_ACTOR_ID, "read");

    final MockHttpServletRequestBuilder regenerateCertificatesRequest = post(API_V1_BULK_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\"signed_by\" : \"" + caName + "\"}");

    this.mockMvc.perform(regenerateCertificatesRequest)
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("The request could not be completed because the credential does not exist or you do not have sufficient authorization.")));

    verifyVersionCountForCertificate(intermediateCert, 1);
    verifyVersionCountForCertificate(leafCert, 1);
  }

  private void verifyVersionCountForCertificate(final String certificateName, final int expectedVersionCount) throws Exception {
    final String certificateId = getCertificateId(mockMvc, certificateName);
    final MockHttpServletRequestBuilder getVersionsRequest = get("/api/v1/certificates/" + certificateId + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8);

    final String versions = this.mockMvc.perform(getVersionsRequest)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    assertThat(new JSONArray(versions).length(), equalTo(expectedVersionCount));
  }

  private String randomCredentialName(final String name) {
    return "/" + name + "-" + UUID.randomUUID().toString();
  }

  private void generateRootCA(final String caName) throws Exception {
    final MockHttpServletRequestBuilder request = post(API_V1_DATA_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"" + caName + "\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "     \"is_ca\": true,\n"
        + "     \"common_name\": \"" + caName + "\"\n"
        + "   }\n"
        + "}");

    this.mockMvc.perform(request)
      .andDo(print())
      .andExpect(status().isOk());
  }

  private void generateSignedCertificate(final String certificateName, final String caName, final boolean isCA) throws Exception {
    final MockHttpServletRequestBuilder request = post(API_V1_DATA_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"" + certificateName + "\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "     \"is_ca\": " + isCA + ",\n"
        + "    \"ca\": \"" + caName + "\",\n"
        + "    \"common_name\": \"" + certificateName + "\"\n"
        + "  },\n"
        + "  \"overwrite\": true\n"
        + "}");

    final String certGenerationResult = this.mockMvc.perform(request)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    assertThat((new JSONObject(certGenerationResult)).getString("value"), notNullValue());
  }

  private void generateSignedCertificate(final String certificateName, final String caName) throws Exception {
    this.generateSignedCertificate(certificateName, caName, false);
  }

  private void grantPermissions(final String credentialName, final String actorId, final String... permissions) throws Exception {
    final String operations = "[\"" + String.join("\", \"", permissions) + "\"]";

    final MockHttpServletRequestBuilder request = post(API_V1_PERMISSION_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\n"
        + "  \"credential_name\": \"" + credentialName + "\",\n"
        + "  \"permissions\": [\n"
        + "     {\n"
        + "       \"actor\": \"" + actorId + "\",\n"
        + "       \"operations\": " + operations + "\n"
        + "     }\n"
        + "   ]\n"
        + "}");

    this.mockMvc.perform(request)
      .andDo(print())
      .andExpect(status().isCreated());
  }

  private void revokePermissions(final String credentialName, final String actorId) throws Exception {
    final MockHttpServletRequestBuilder request = delete(API_V1_PERMISSION_ENDPOINT + "?credential_name=" + credentialName + "&actor=" + actorId)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isNoContent());
  }
}
