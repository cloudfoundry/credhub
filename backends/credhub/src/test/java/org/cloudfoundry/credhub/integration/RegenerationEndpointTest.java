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

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
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
@Transactional
public class RegenerationEndpointTest {

  private static final String API_V1_DATA_ENDPOINT = "/api/v1/data";
  private static final String API_V1_REGENERATE_ENDPOINT = "/api/v1/regenerate";
  private static final String CREDENTIAL_NAME = "some-credential";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private String originalPassword;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    final MockHttpServletRequestBuilder generatePasswordRequest = post(API_V1_DATA_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
        + "  \"type\" : \"password\"\n"
        + "}");

    final String generatePasswordResult = this.mockMvc.perform(generatePasswordRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    originalPassword = (new JSONObject(generatePasswordResult)).getString("value");
    assertThat(originalPassword, notNullValue());
  }

  @Test
  public void passwordRegeneration_withDefaultParameters_shouldRegeneratePassword() throws Exception {
    final MockHttpServletRequestBuilder regeneratePasswordRequest = post(API_V1_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"" + CREDENTIAL_NAME + "\"\n"
        + "}");

    final String regeneratePasswordResult = this.mockMvc.perform(regeneratePasswordRequest)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String regeneratedPassword = (new JSONObject(regeneratePasswordResult)).getString("value");

    assertThat(regeneratedPassword, notNullValue());
    assertThat(regeneratedPassword, not(equalTo(originalPassword)));
  }

  @Test
  public void passwordRegeneration_withoutWritePermissionShouldFail() throws Exception {
    final MockHttpServletRequestBuilder regeneratePasswordRequest = post(API_V1_REGENERATE_ENDPOINT)
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"" + CREDENTIAL_NAME + "\"\n"
        + "}");

    this.mockMvc.perform(regeneratePasswordRequest)
      .andDo(print())
      .andExpect(status().isForbidden());
  }
}
