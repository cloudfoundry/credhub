package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
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
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.cloudfoundry.credhub.utils.CertificateStringConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_PATH;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredhubTestApp.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@Transactional
public class CredentialAclEnforcementTest {
  private static final String CREDENTIAL_NAME = "/TEST/CREDENTIAL";
  private static final String SECOND_CREDENTIAL_NAME = "/TEST/CREDENTIAL2";

  @Autowired
  WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private String uuid;

  @Before
  public void setup() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    generatePassword(CREDENTIAL_NAME);
    uuid = generatePassword(CREDENTIAL_NAME);
    grantPermissions(CREDENTIAL_NAME, USER_A_ACTOR_ID, "read", "read_acl");

    generatePassword(SECOND_CREDENTIAL_NAME);
    grantPermissions(SECOND_CREDENTIAL_NAME, USER_A_ACTOR_ID, "read", "read_acl", "write");
  }

  @Test
  public void GET_byCredentialName_whenTheUserHasPermissionToReadCredential_returnsTheCredential() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + USER_A_TOKEN);
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.data[0].type", equalTo("password")))
      .andExpect(jsonPath("$.data[0].name", equalTo(CREDENTIAL_NAME)));
  }

  @Test
  public void GET_byCredentialName_whenTheUserDoesntHavePermissionToReadCredential_returns404() throws Exception {
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT);
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .with(SecurityMockMvcRequestPostProcessors
        .x509(certificateReader.getCertificate()));
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void GET_byId_whenTheUserHasPermissionToReadCredential_returnsTheCredential() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data/" + uuid)
      .header("Authorization", "Bearer " + USER_A_TOKEN);
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.type", equalTo("password")))
      .andExpect(jsonPath("$.name", equalTo(CREDENTIAL_NAME)));
  }

  @Test
  public void GET_byId_whenTheUserDoesntHavePermissionToReadCredential_returns404() throws Exception {
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT);
    final MockHttpServletRequestBuilder get = get("/api/v1/data/" + uuid)
      .with(SecurityMockMvcRequestPostProcessors
        .x509(certificateReader.getCertificate()));
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void GET_byVersions_whenTheUserHasPermissionToReadCredential_returnsCredentialVersions() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME + "&versions=2")
      .header("Authorization", "Bearer " + USER_A_TOKEN);
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.data[0].type", equalTo("password")))
      .andExpect(jsonPath("$.data[1].type", equalTo("password")))
      .andExpect(jsonPath("$.data[0].name", equalTo(CREDENTIAL_NAME)))
      .andExpect(jsonPath("$.data[1].name", equalTo(CREDENTIAL_NAME)));
  }

  @Test
  public void GET_byVersions_whenTheUserDoesntHavePermissionToReadCredential_returns404() throws Exception {
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT);
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME + "&versions=2")
      .with(SecurityMockMvcRequestPostProcessors
        .x509(certificateReader.getCertificate()));
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void PUT_whenTheUserLacksPermissionToWrite_returnsAccessDenied() throws Exception {
    final MockHttpServletRequestBuilder edit = put("/api/v1/data")
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      // language=JSON
      .content("{\n"
        + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
        + "  \"value\" : \"Resistance is futile\",\n"
        + "  \"type\" : \"password\"\n"
        + "}")
      .accept(APPLICATION_JSON);

    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(edit)
      .andDo(print())
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void POST_whenTheUserLacksPermissionToWrite_returnsAccessDenied() throws Exception {
    final MockHttpServletRequestBuilder edit = post("/api/v1/data")
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      // language=JSON
      .content("{\n"
        + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
        + "  \"type\" : \"password\"\n"
        + "}")
      .accept(APPLICATION_JSON);

    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(edit)
      .andDo(print())
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void POST_whenTheUserHasPermissionToWrite_succeeds() throws Exception {
    final MockHttpServletRequestBuilder edit = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      // language=JSON
      .content("{\n"
        + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
        + "  \"type\" : \"password\"\n"
        + "}")
      .accept(APPLICATION_JSON);

    this.mockMvc.perform(edit)
      .andDo(print())
      .andExpect(status().is2xxSuccessful());
  }

  @Test
  public void DELETE_whenTheUserHasPermissionToDeleteTheCredential_succeeds() throws Exception {
    final MockHttpServletRequestBuilder deleteRequest = delete(
      "/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN);
    mockMvc.perform(deleteRequest)
      .andExpect(status().isNoContent());

    final MockHttpServletRequestBuilder getRequest = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN);
    mockMvc.perform(getRequest)
      .andExpect(status().isNotFound());
  }

  @Test
  public void DELETE_whenTheUserLacksPermissionToDeleteTheCredential_returns404() throws Exception {
    final MockHttpServletRequestBuilder deleteRequest = delete(
      "/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + USER_A_TOKEN);
    mockMvc.perform(deleteRequest)
      .andExpect(status().isNotFound());

    final MockHttpServletRequestBuilder getRequest = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN);
    mockMvc.perform(getRequest)
      .andExpect(status().isOk());
  }

  @Test
  public void interpolate_whenTheUserHasAccessToAllReferencedCredentials_returnsInterpolatedBody() throws Exception {
    makeJsonCredential(ALL_PERMISSIONS_TOKEN, "secret1");
    makeJsonCredential(ALL_PERMISSIONS_TOKEN, "secret2");

    final MockHttpServletRequestBuilder request = post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(
        "{" +
          "    \"pp-config-server\": [" +
          "      {" +
          "        \"credentials\": {" +
          "          \"credhub-ref\": \"/secret1\"" +
          "        }," +
          "        \"label\": \"pp-config-server\"" +
          "      }" +
          "    ]," +
          "    \"pp-something-else\": [" +
          "      {" +
          "        \"credentials\": {" +
          "          \"credhub-ref\": \"/secret2\"" +
          "        }," +
          "        \"something\": [\"pp-config-server\"]" +
          "      }" +
          "    ]" +
          "  }"
      );

    this.mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.pp-config-server[0].credentials.secret1")
        .value(equalTo("secret1-value")))
      .andExpect(jsonPath("$.pp-something-else[0].credentials.secret2")
        .value(equalTo("secret2-value")));
  }

  @Test
  public void interpolate_whenTheUserDoesNotHaveAccessToAllReferencedCredentials_returnsAnError() throws Exception {
    makeJsonCredential(ALL_PERMISSIONS_TOKEN, "secret1");
    makeJsonCredential(USER_A_TOKEN, USER_A_PATH + "secret2");

    final MockHttpServletRequestBuilder request = post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(
        "{" +
          "    \"pp-config-server\": [" +
          "      {" +
          "        \"credentials\": {" +
          "          \"credhub-ref\": \"/secret1\"" +
          "        }," +
          "        \"label\": \"pp-config-server\"" +
          "      }" +
          "    ]," +
          "    \"pp-something-else\": [" +
          "      {" +
          "        \"credentials\": {" +
          "          \"credhub-ref\": \"" + USER_A_PATH + "secret2\"" +
          "        }," +
          "        \"something\": [\"pp-config-server\"]" +
          "      }" +
          "    ]" +
          "  }"
      );

    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(request)
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  private String generatePassword(final String credentialName) throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON_UTF8)
      //language=JSON
      .content("{\n"
        + "  \"name\": \"" + credentialName + "\",\n"
        + "  \"type\": \"password\",\n"
        + "  \"overwrite\": true\n"
        + "}");

    final String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn()
      .getResponse().getContentAsString();
    return JsonPath.parse(response).read("$.id");
  }

  private void grantPermissions(final String credentialName, final String actorId, final String... permissions) throws Exception {
    final String operations = "[\"" + String.join("\", \"", permissions) + "\"]";

    final MockHttpServletRequestBuilder request = post("/api/v1/permissions")
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

  private void makeJsonCredential(final String userToken, final String credentialName) throws Exception {
    final MockHttpServletRequestBuilder createRequest1 = put("/api/v1/data")
      .header("Authorization", "Bearer " + userToken)
      .contentType(MediaType.APPLICATION_JSON)
      .content(
        "{" +
          "\"name\":\"" + credentialName + "\"," +
          "\"type\":\"json\"," +
          "\"value\":{" +
          "\"" + credentialName + "\":\"" + credentialName + "-value\"" +
          "}" +
          "}"
      );
    this.mockMvc.perform(createRequest1)
      .andExpect(status().isOk());
  }
}
