package org.cloudfoundry.credhub.integration;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.apache.commons.lang3.math.NumberUtils.isDigits;
import static org.cloudfoundry.credhub.helper.RequestHelper.generateUser;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class UserGenerationTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  private final String credentialName1 = "/" + this.getClass().getSimpleName() + "1";
  private final String credentialName2 = "/" + this.getClass().getSimpleName() + "2";

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void generatesCorrectUsernameAndPassword() throws Exception {
    getPost(credentialName1);
    getPost(credentialName2);

    MvcResult cred1 = this.mockMvc.perform(get("/api/v1/data?name=" + credentialName1)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].value.username", isUsername()))
        .andExpect(jsonPath("$.data[0].value.password", isPassword()))
        .andReturn();


    MvcResult cred2 = this.mockMvc.perform(get("/api/v1/data?name=" + credentialName2)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].value.username", isUsername()))
        .andExpect(jsonPath("$.data[0].value.password", isPassword()))
        .andReturn();

    JSONObject jsonCred1 = getJsonObject(cred1);
    JSONObject jsonCred2 = getJsonObject(cred2);

    assertThat(jsonCred1.getString("username"), not(equalTo(jsonCred2.getString("username"))));
    assertThat(jsonCred1.getString("password"), not(equalTo(jsonCred2.getString("password"))));
  }

  @Test
  public void generatesOnlyPasswordWhenGivenStaticUsernameProvidedInValues() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{  \"name\": \"" + credentialName1 + "\", \n" +
            "  \"type\": \"user\", \n" +
            "  \"value\": {\n" +
            "    \"username\": \"luke\" \n" +
            "  }\n" +
            "}");

    this.mockMvc.perform(post)
        .andDo(print())
        .andExpect(status().isOk());

    this.mockMvc.perform(get("/api/v1/data?name=" + credentialName1)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].value.username", equalTo("luke")))
        .andExpect(jsonPath("$.data[0].value.password", isPassword()))
        .andReturn();
  }

  @Test
  public void generatesOnlyPasswordWhenGivenStaticUsernameProvidedInParams() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{  \"name\": \"" + credentialName1 + "\", \n" +
            "  \"type\": \"user\", \n" +
            "  \"parameters\": {\n" +
            "    \"username\": \"luke\" \n" +
            "  }\n" +
            "}");

    this.mockMvc.perform(post)
        .andDo(print())
        .andExpect(status().isOk());

    this.mockMvc.perform(get("/api/v1/data?name=" + credentialName1)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].value.username", equalTo("luke")))
        .andExpect(jsonPath("$.data[0].value.password", isPassword()))
        .andReturn();
  }

  @Test
  public void whenGivenPasswordParameters_shouldGeneratePasswordFromParameters() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\": \"" + credentialName1 + "\"," +
            "\"type\": \"user\"," +
            "\"parameters\": {" +
            "\"length\": 40," +
            "\"exclude_upper\": true," +
            "\"exclude_lower\": true," +
            "\"exclude_number\": false," +
            "\"include_special\": false" +
            "}" +
            "}"
        );

    final MockHttpServletResponse response = this.mockMvc.perform(post).andExpect(status()
        .isOk()).andReturn().getResponse();

    final DocumentContext parsedResponse = JsonPath.parse(response.getContentAsString());

    final String password = parsedResponse.read("$.value.password");
    assertThat(password.length(), equalTo(40));
    assertThat(isDigits(password), equalTo(true));

    final String username = parsedResponse.read("$.value.username");
    assertThat(username.length(), equalTo(20));
    assertThat(username.chars().allMatch(Character::isLetter), equalTo(true));
  }

  @Test
  public void whenGivenAUsernameAndPasswordParameters_usesUsernameAndGeneratesPassword() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\": \"" + credentialName1 + "\"," +
            "\"type\": \"user\"," +
            "\"value\": {" +
            "\"username\": \"test-username\"" +
            "}," +
            "\"parameters\": {" +
            "\"length\": 40," +
            "\"exclude_upper\": true," +
            "\"exclude_lower\": true," +
            "\"exclude_number\": false," +
            "\"include_special\": false" +
            "}" +
            "}"
        );

    final MockHttpServletResponse response = this.mockMvc.perform(post).andExpect(status()
        .isOk()).andReturn().getResponse();

    final DocumentContext parsedResponse = JsonPath.parse(response.getContentAsString());

    final String password = parsedResponse.read("$.value.password");
    assertThat(password.length(), equalTo(40));
    assertThat(isDigits(password), equalTo(true));

    final String username = parsedResponse.read("$.value.username");
    assertThat(username, equalTo("test-username"));
  }

  @Test
  public void returnsAConsistentPasswordHash() throws Exception {
    MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\": \"" + credentialName1 + "\"," +
            "\"type\": \"user\"," +
            "\"value\": {" +
            "\"username\": \"test-username\"" +
            "}" +
            "}"
        );

    final MockHttpServletResponse postResponse = this.mockMvc.perform(postRequest)
        .andExpect(status().isOk())
        .andReturn()
        .getResponse();

    final MockHttpServletRequestBuilder getRequest = get("/api/v1/data?name=" + credentialName1)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    final MockHttpServletResponse getResponse = this.mockMvc.perform(getRequest)
        .andExpect(status().isOk())
        .andReturn()
        .getResponse();


    final DocumentContext parsedPostResponse = JsonPath.parse(postResponse.getContentAsString());
    final DocumentContext parsedGetResponse = JsonPath.parse(getResponse.getContentAsString());

    final String postHash = parsedPostResponse.read("$.value.password_hash");
    final String getHash = parsedGetResponse.read("$.data[0].value.password_hash");

    assertThat(postHash, equalTo(getHash));
    assertThat(postHash.matches("^\\$6\\$[a-zA-Z0-9/.]+\\$[a-zA-Z0-9/.]+$"), equalTo(true));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSame() throws Exception {
    String firstResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.OVERWRITE.mode, 20, null, false);
    String originalUsername = (new JSONObject(firstResponse)).getJSONObject("value").getString("username");
    String originalPassword = (new JSONObject(firstResponse)).getJSONObject("value").getString("password");

    String secondResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.CONVERGE.mode, 20, null, false);
    String secondUsername = (new JSONObject(secondResponse)).getJSONObject("value").getString("username");
    String secondPassword = (new JSONObject(secondResponse)).getJSONObject("value").getString("password");

    assertThat(originalPassword, Matchers.equalTo(secondPassword));
    assertThat(originalUsername, Matchers.equalTo(secondUsername));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSameAndAreTheDefaults() throws Exception {
    String firstResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.OVERWRITE.mode, null, null, false);
    String originalUsername = (new JSONObject(firstResponse)).getJSONObject("value").getString("username");
    String originalPassword = (new JSONObject(firstResponse)).getJSONObject("value").getString("password");

    String secondResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.CONVERGE.mode, null, null, false);
    String secondUsername = (new JSONObject(secondResponse)).getJSONObject("value").getString("username");
    String secondPassword = (new JSONObject(secondResponse)).getJSONObject("value").getString("password");

    assertThat(originalPassword, Matchers.equalTo(secondPassword));
    assertThat(originalUsername, Matchers.equalTo(secondUsername));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndParametersNotTheSame() throws Exception {
    String firstResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.OVERWRITE.mode, 30, null, false);
    String originalUsername = (new JSONObject(firstResponse)).getJSONObject("value").getString("username");
    String originalPassword = (new JSONObject(firstResponse)).getJSONObject("value").getString("password");

    String secondResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.CONVERGE.mode, 20, null, false);
    String secondUsername = (new JSONObject(secondResponse)).getJSONObject("value").getString("username");
    String secondPassword = (new JSONObject(secondResponse)).getJSONObject("value").getString("password");

    assertThat(originalPassword, not(Matchers.equalTo(secondPassword)));
    assertThat(secondPassword.length(), equalTo(20));
    assertThat(originalUsername, not(Matchers.equalTo(secondUsername)));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndUsernameNotTheSame() throws Exception {
    generateUser(mockMvc, credentialName1, CredentialWriteMode.OVERWRITE.mode, null, "original-username", false);

    String secondResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.CONVERGE.mode, null, "updated-username", false);
    String secondUsername = (new JSONObject(secondResponse)).getJSONObject("value").getString("username");

    assertThat(secondUsername, Matchers.equalTo("updated-username"));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndUsernameIsNotProvidedInTheSecondRequest() throws Exception {
    generateUser(mockMvc, credentialName1, CredentialWriteMode.OVERWRITE.mode, null, "original-username", false);

    String secondResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.CONVERGE.mode, null, null, false);
    String secondUsername = (new JSONObject(secondResponse)).getJSONObject("value").getString("username");

    assertThat(secondUsername, not(equalTo("original-username")));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndPasswordParametersNotTheSame() throws Exception {
    String firstResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.OVERWRITE.mode, 20, null, true);
    String originalUsername = (new JSONObject(firstResponse)).getJSONObject("value").getString("username");
    String originalPassword = (new JSONObject(firstResponse)).getJSONObject("value").getString("password");

    String secondResponse = generateUser(mockMvc, credentialName1, CredentialWriteMode.CONVERGE.mode, 20, null, false);
    String secondUsername = (new JSONObject(secondResponse)).getJSONObject("value").getString("username");
    String secondPassword = (new JSONObject(secondResponse)).getJSONObject("value").getString("password");

    assertThat(originalPassword, not(Matchers.equalTo(secondPassword)));
    assertThat(secondPassword.length(), equalTo(20));
    assertThat(originalUsername, not(Matchers.equalTo(secondUsername)));
  }

  private JSONObject getJsonObject(MvcResult cred1) throws Exception {
    JSONObject jsonCred1 = new JSONObject(cred1.getResponse().getContentAsString());
    return jsonCred1
        .getJSONArray("data")
        .getJSONObject(0)
        .getJSONObject("value");
  }

  private void getPost(String name) throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + name + "\","
            + "  \"type\": \"user\""
            + "}");

    this.mockMvc.perform(post)
        .andExpect(status().isOk());
  }

  private Matcher<String> isUsername() {
    return new BaseMatcher<String>() {
      @Override
      public boolean matches(final Object item) {
        final String username = (String) item;
        boolean matches = username.length() == 20;
        matches = matches && username.matches("[a-zA-Z]+");
        return matches;
      }

      @Override
      public void describeTo(final Description description) {
        description.appendText("a 20 character string with only alpha characters");
      }
    };
  }

  private Matcher<String> isPassword() {
    return new BaseMatcher<String>() {
      @Override
      public boolean matches(final Object item) {
        final String username = (String) item;
        boolean matches = username.length() == 30;
        matches = matches && username.matches("[a-zA-Z0-9]+");
        return matches;
      }

      @Override
      public void describeTo(final Description description) {
        description.appendText("a 30 character string with only alpha numeric characters");
      }
    };
  }
}
