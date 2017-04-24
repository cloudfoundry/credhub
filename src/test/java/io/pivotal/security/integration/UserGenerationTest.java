package io.pivotal.security.integration;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.UnsupportedEncodingException;

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.apache.commons.lang.math.NumberUtils.isNumber;
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

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class UserGenerationTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    cleanUpDatabase(webApplicationContext);
  }


  @Test
  public void userGeneration_shouldGenerateCorrectUsernameAndPassword() throws Exception {
    getPost("/cred1");
    getPost("/cred2");

    MvcResult cred1 = this.mockMvc.perform(get("/api/v1/data?name=/cred1")
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.data[0].value.username", isUsername()))
      .andExpect(jsonPath("$.data[0].value.password", isPassword()))
      .andReturn();


    MvcResult cred2 = this.mockMvc.perform(get("/api/v1/data?name=/cred2")
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
  public void userGeneration_shouldGenerateOnlyPasswordWhenGivenStaticUsername() throws Exception{
    MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{  \"name\": \"cred1\", \n" +
        "  \"type\": \"user\", \n" +
        "  \"value\": {\n" +
        "    \"username\": \"luke\" \n" +
        "  }\n" +
        "}");

    this.mockMvc.perform(post)
      .andDo(print())
      .andExpect(status().isOk());

    this.mockMvc.perform(get("/api/v1/data?name=/cred1")
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.data[0].value.username", equalTo("luke")))
      .andExpect(jsonPath("$.data[0].value.password", isPassword()))
      .andReturn();
  }

  @Test
  public void userGeneration_whenGivenPasswordParameters_shouldGeneratePasswordFromParameters() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\": \"cred1\"," +
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
    assertThat(isNumber(password), equalTo(true));

    final String username = parsedResponse.read("$.value.username");
    assertThat(username.length(), equalTo(20));
    assertThat(username.chars().allMatch(Character::isLetter), equalTo(true));
  }

  @Test
  public void userGeneration_whenGivenAUsernameAndPasswordParameters_usesUsernameAndGeneratesPassword() throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\": \"cred1\"," +
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
    assertThat(isNumber(password), equalTo(true));

    final String username = parsedResponse.read("$.value.username");
    assertThat(username, equalTo("test-username"));
  }

  private JSONObject getJsonObject(MvcResult cred1) throws UnsupportedEncodingException {
    JSONObject jsonCred1 = new JSONObject(cred1.getResponse().getContentAsString());
    return jsonCred1
        .getJSONArray("data")
        .getJSONObject(0)
        .getJSONObject("value");
  }

  private static void cleanUpDatabase(ApplicationContext applicationContext) {
    JdbcTemplate jdbcTemplate = applicationContext.getBean(JdbcTemplate.class);
    jdbcTemplate.execute("delete from credential_name");
    jdbcTemplate.execute("truncate table auth_failure_audit_record");
    jdbcTemplate.execute("delete from event_audit_record");
    jdbcTemplate.execute("delete from request_audit_record");
    jdbcTemplate.execute("delete from encryption_key_canary");
    jdbcTemplate.execute("truncate table access_entry");

    EncryptionKeyCanaryMapper encryptionKeyCanaryMapper = applicationContext
        .getBean(EncryptionKeyCanaryMapper.class);
    encryptionKeyCanaryMapper.mapUuidsToKeys();
  }


  private void getPost(String name) throws Exception {
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
