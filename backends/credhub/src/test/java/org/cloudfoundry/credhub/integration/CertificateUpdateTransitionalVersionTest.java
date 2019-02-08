package org.cloudfoundry.credhub.integration;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateCredentialsByName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CertificateUpdateTransitionalVersionTest {

  private static final String caName = "/some-ca";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private Object caCertificate;
  private String caCredentialUuid;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    final String generateCaResponse = generateCa(mockMvc, caName, ALL_PERMISSIONS_TOKEN);
    caCertificate = JsonPath.parse(generateCaResponse)
      .read("$.value.certificate");
    final String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, caName);
    caCredentialUuid = JsonPath.parse(response)
      .read("$.certificates[0].id");
    assertNotNull(caCertificate);
  }

  @Test
  public void certificateUpdateTransitionalVersion_changesValueOfTransitionalFlag() throws Exception {
    final MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"set_as_transitional\": true" +
        "}");

    this.mockMvc.perform(regenerateRequest)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.transitional", equalTo(true)));

    final MockHttpServletRequestBuilder versionsRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String versionsResponse = this.mockMvc.perform(versionsRequest)
      .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

    final String originalVersion = new JSONArray(versionsResponse).get(1).toString();
    final String regeneratedVersion = new JSONArray(versionsResponse).get(0).toString();

    assertThat(JsonPath.parse(regeneratedVersion).read("transitional"), equalTo(true));
    final String originalVersionId = JsonPath.parse(originalVersion).read("id");

    final MockHttpServletRequestBuilder updateTransitionalRequest = put(
      "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"version\": \"" + originalVersionId + "\"" +
        "}");

    this.mockMvc.perform(updateTransitionalRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].transitional", equalTo(false)))
      .andExpect(jsonPath("$[1].transitional", equalTo(true)))
      .andExpect(jsonPath("$[1].id", equalTo(originalVersionId)));
  }

  @Test
  public void certificateUpdateTransitionalVersion_whenThereIsNoExistingTransitionalVersion_changesValueOfTransitionalFlag()
    throws Exception {
    final MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    this.mockMvc.perform(regenerateRequest)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.transitional", equalTo(false)));

    final MockHttpServletRequestBuilder versionsRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String versionsResponse = this.mockMvc.perform(versionsRequest)
      .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

    final String originalVersion = new JSONArray(versionsResponse).get(1).toString();
    final String originalVersionId = JsonPath.parse(originalVersion).read("id");

    final MockHttpServletRequestBuilder updateTransitionalRequest = put(
      "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"version\": \"" + originalVersionId + "\"" +
        "}");

    this.mockMvc.perform(updateTransitionalRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].transitional", equalTo(false)))
      .andExpect(jsonPath("$[1].transitional", equalTo(true)))
      .andExpect(jsonPath("$[1].id", equalTo(originalVersionId)));
  }

  @Test
  public void certificateUpdateTransitionalVersion_whenNoVersionIdIsProvided_unSetsTransitionalFlag() throws Exception {
    final MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    this.mockMvc.perform(regenerateRequest)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.transitional", equalTo(false)));

    final MockHttpServletRequestBuilder versionsRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String versionsResponse = this.mockMvc.perform(versionsRequest)
      .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

    final String regeneratedVersion = new JSONArray(versionsResponse).get(0).toString();
    final String regeneratedVersionId = JsonPath.parse(regeneratedVersion).read("id");

    final MockHttpServletRequestBuilder updateTransitionalRequest = put(
      "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{}");

    this.mockMvc.perform(updateTransitionalRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].transitional", equalTo(false)))
      .andExpect(jsonPath("$[0].id", equalTo(regeneratedVersionId)));
  }
}
