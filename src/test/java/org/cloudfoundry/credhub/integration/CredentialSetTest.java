package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.util.AuthConstants;
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

import static org.cloudfoundry.credhub.helper.RequestHelper.setPassword;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialSetTest {
  private static final String CREDENTIAL_NAME = "/set_credential";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private Object caCertificate;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void whenUserProvidesBothOverwriteAndMode_returnsAnError() throws Exception {
    MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\n"
            + "  \"name\" : \"name\",\n"
            + "  \"type\" : \"password\",\n"
            + "  \"overwrite\" : false,\n"
            + "  \"value\" : \"some-password\",\n"
            + "  \"mode\" : \"no-overwrite\"\n"
            + "}");

    String response = mockMvc.perform(put)
        .andExpect(status().isBadRequest())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The parameters overwrite and mode cannot be combined. Please update and retry your request."));
  }

  @Test
  public void rsaCredentialCanBeSetWithoutPrivateKey() throws Exception {
    MockHttpServletRequestBuilder setRsaRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" :\"" + CREDENTIAL_NAME + "\",\n"
            + "  \"type\" : \"rsa\",\n"
            + "  \"value\" : {\n"
            + "    \"public_key\" : \"a_certain_public_key\",\n"
            + "    \"private_key\" : \"\"\n"
            + "  }\n"
            + "}");

    this.mockMvc
        .perform(setRsaRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse()
        .getContentAsString();

  }

  @Test
  public void userCredentialReturnsNullUsernameWhenSetWithBlankStringAsUsername() throws Exception {
    MockHttpServletRequestBuilder setUserRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" :\"" + CREDENTIAL_NAME + "\",\n"
            + "  \"type\" : \"user\",\n"
            + "  \"value\" : {\n"
            + "    \"username\" : \"\",\n"
            + "    \"password\" : \"some_silly_password\"\n"
            + "  }\n"
            + "}");

    String response = this.mockMvc
        .perform(setUserRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse()
        .getContentAsString();

    assertThat(response, containsString("\"username\":null"));
  }

  @Test
  public void credentialCanBeOverwrittenWhenModeIsSetToOverwriteInRequest() throws Exception {
    setPassword(mockMvc, CREDENTIAL_NAME, "original-password", CredentialWriteMode.NO_OVERWRITE.mode);

    String secondResponse = setPassword(mockMvc, CREDENTIAL_NAME, "new-password", CredentialWriteMode.OVERWRITE.mode);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(updatedPassword, equalTo("new-password"));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToNotOverwriteInRequest() throws Exception {
    setPassword(mockMvc, CREDENTIAL_NAME, "original-password", CredentialWriteMode.NO_OVERWRITE.mode);

    String secondResponse = setPassword(mockMvc, CREDENTIAL_NAME, "new-password", CredentialWriteMode.NO_OVERWRITE.mode);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(updatedPassword, equalTo("original-password"));
  }
}
