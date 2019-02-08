package org.cloudfoundry.credhub.integration;


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

import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.helpers.RequestHelper;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateCredentialsByName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CertificateVersionDeleteTest {
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
  public void deleteCertificateVersion_whenThereAreOtherVersionsOfTheCertificate_deletesTheSpecifiedVersion() throws Exception {
    final String credentialName = "/test-certificate";

    String response = generateCertificateCredential(mockMvc, credentialName, true, "test", null, ALL_PERMISSIONS_TOKEN);
    final String nonDeletedVersion = JsonPath.parse(response).read("$.value.certificate");

    response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, credentialName);
    final String uuid = JsonPath.parse(response)
      .read("$.certificates[0].id");

    final String version = RequestHelper.regenerateCertificate(mockMvc, uuid, false, ALL_PERMISSIONS_TOKEN);
    final String versionUuid = JsonPath.parse(version).read("$.id");
    final String versionValue = JsonPath.parse(version).read("$.value.certificate");

    final MockHttpServletRequestBuilder request = delete("/api/v1/certificates/" + uuid + "/versions/" + versionUuid)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String certificate = JsonPath.parse(response)
      .read("$.value.certificate");
    assertThat(certificate, equalTo(versionValue));

    response = mockMvc.perform(get("/api/v1/certificates/" + uuid + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)).andReturn().getResponse().getContentAsString();

    final JSONArray jsonArray = new JSONArray(response);
    assertThat(jsonArray.length(), equalTo(1));
    assertThat(JsonPath.parse(jsonArray.get(0).toString()).read("$.value.certificate"), equalTo(nonDeletedVersion));
  }

  @Test
  public void deleteCertificateVersion_whenThereAreNoOtherVersionsOfTheCertificate_returnsAnError() throws Exception {
    final String credentialName = "/test-certificate";

    String response = generateCertificateCredential(mockMvc, credentialName, true, "test", null, ALL_PERMISSIONS_TOKEN);
    final String versionUuid = JsonPath.parse(response).read("$.id");

    response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, credentialName);
    final String uuid = JsonPath.parse(response)
      .read("$.certificates[0].id");

    final MockHttpServletRequestBuilder request = delete("/api/v1/certificates/" + uuid + "/versions/" + versionUuid)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("The minimum number of versions for a Certificate is 1.")));
  }
}
