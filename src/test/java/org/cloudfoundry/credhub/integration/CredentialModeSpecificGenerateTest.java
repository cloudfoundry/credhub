package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.json.JSONObject;
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

import static org.cloudfoundry.credhub.helper.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialModeSpecificGenerateTest {
  private static final String CREDENTIAL_NAME = "/set_credential";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void setup() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void whenUserProvidesBothOverwriteAndMode_returnsAnError() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\n"
            + "  \"name\" : \"name\",\n"
            + "  \"type\" : \"password\",\n"
            + "  \"overwrite\" : false,\n"
            + "  \"mode\" : \"no-overwrite\"\n"
            + "}");

    String response = mockMvc.perform(post)
        .andExpect(status().isBadRequest())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The parameters overwrite and mode cannot be combined. Please update and retry your request."));
  }

  @Test
  public void credentialCanBeOverwrittenWhenModeIsSetToOverwriteInRequest() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, null);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, null);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, not(equalTo(updatedPassword)));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToNotOverwriteInRequest() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, null);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.NO_OVERWRITE.mode, null);
    String samePassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(samePassword));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSame() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, 20);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, 20);
    String samePassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(samePassword));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSameAndAreTheDefault() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, null);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, null);
    String samePassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(samePassword));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndParametersNotTheSame() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, 30);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, 20);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, not(equalTo(updatedPassword)));
  }

  @Test
  public void credentialNotOverwrittenWhenNameIsProvidedWithoutASlashAndThenWithOne() throws Exception {
    String firstResponse = generatePassword(mockMvc, "a-name", CredentialWriteMode.OVERWRITE.mode, 30);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, "/a-name", CredentialWriteMode.NO_OVERWRITE.mode, 20);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(updatedPassword));
  }
}
