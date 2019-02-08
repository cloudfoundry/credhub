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
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class PasswordRegenerationTest {

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
  public void passwordRegeneration_withDefaultParameters_shouldRegeneratePassword() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\"\n"
        + "}");

    final String caResult = this.mockMvc.perform(post)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String originalPassword = (new JSONObject(caResult)).getString("value");

    assertThat(originalPassword, notNullValue());

    final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"regenerate\" : true\n"
        + "}");

    final String regenerateResult = this.mockMvc.perform(regeneratePost)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String regeneratedPassword = (new JSONObject(regenerateResult)).getString("value");

    assertThat(regeneratedPassword, notNullValue());
    assertThat(regeneratedPassword, not(equalTo(originalPassword)));
  }

  @Test
  public void passwordRegeneration_withoutOverwrite_shouldNotRegeneratePassword() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\"\n"
        + "}");

    final String caResult = this.mockMvc.perform(post)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String originalPassword = (new JSONObject(caResult)).getString("value");

    assertThat(originalPassword, notNullValue());

    final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\"\n"
        + "}");

    final String regenerateResult = this.mockMvc.perform(regeneratePost)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String regeneratedPassword = (new JSONObject(regenerateResult)).getString("value");

    assertThat(regeneratedPassword, notNullValue());
    assertThat(regeneratedPassword, equalTo(originalPassword));
  }

  @Test
  public void passwordRegeneration_withOverwrite_shouldRegeneratePassword() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\"\n"
        + "}");

    final String caResult = this.mockMvc.perform(post)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String originalPassword = (new JSONObject(caResult)).getString("value");

    assertThat(originalPassword, notNullValue());

    final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\",\n"
        + "  \"overwrite\" : true }");

    final String regenerateResult = this.mockMvc.perform(regeneratePost)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String regeneratedPassword = (new JSONObject(regenerateResult)).getString("value");

    assertThat(regeneratedPassword, notNullValue());
    assertThat(regeneratedPassword, not(equalTo(originalPassword)));
  }

  @Test
  public void passwordRegeneration_withoutOverwrite_butChangingParameter_shouldRegeneratePassword() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\",\n"
        + "  \"parameters\" : {\n"
        + "  \"length\" : 20"
        + "}"
        + "}");

    final String caResult = this.mockMvc.perform(post)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String originalPassword = (new JSONObject(caResult)).getString("value");

    assertThat(originalPassword, notNullValue());

    final MockHttpServletRequestBuilder regeneratePost = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"picard\",\n"
        + "  \"type\" : \"password\",\n"
        + "  \"parameters\" : {\n"
        + "  \"length\" : 40"
        + "}"
        + "}");

    final String regenerateResult = this.mockMvc.perform(regeneratePost)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String regeneratedPassword = (new JSONObject(regenerateResult)).getString("value");

    assertThat(regeneratedPassword, notNullValue());
    assertThat(regeneratedPassword, not(equalTo(originalPassword)));
  }

}
