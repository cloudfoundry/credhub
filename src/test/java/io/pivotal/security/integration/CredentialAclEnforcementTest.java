package io.pivotal.security.integration;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT;
import static io.pivotal.security.util.X509TestUtil.cert;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
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
    seedCredential();
  }

  @Test
  public void GET_byCredentialName_whenTheUserHasPermissionToReadCredential_returnsTheCredential() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].type", equalTo("password")))
        .andExpect(jsonPath("$.data[0].name", equalTo(CREDENTIAL_NAME)));
  }

  @Test
  public void GET_byCredentialName_whenTheUserDoesntHavePermissionToReadCredential_returns404() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME)
        .with(x509(cert(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)));
    mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error", equalTo("Credential not found. Please validate your input and retry your request.")));
  }

  @Test
  public void GET_byId_whenTheUserHasPermissionToReadCredential_returnsTheCredential() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data/" + uuid)
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.type", equalTo("password")))
        .andExpect(jsonPath("$.name", equalTo(CREDENTIAL_NAME)));
  }

  @Test
  public void GET_byId_whenTheUserDoesntHavePermissionToReadCredential_returns404() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data/" + uuid)
        .with(x509(cert(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)));
    mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error", equalTo("Credential not found. Please validate your input and retry your request.")));
  }

  @Test
  public void PUT_whenTheUserLacksPermissionToReadTheAcl_returnsAccessDenied() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
            + "  \"value\" : \"Resistance is futile\",\n"
            + "  \"type\" : \"password\"\n"
            + "}")
        .accept(APPLICATION_JSON);

    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(edit)
        .andDo(print())
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void PUT_whenTheUserHasPermissionToWriteAnAcl_succeeds() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
            + "  \"value\" : \"Resistance is futile\",\n"
            + "  \"type\" : \"password\"\n"
            + "}")
        .accept(APPLICATION_JSON);

    this.mockMvc.perform(edit)
        .andDo(print())
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  public void PUT_whenTheUserLacksPermissionToWriteAnAcl_returnsAccessDenied() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + SECOND_CREDENTIAL_NAME + "\",\n"
            + "  \"value\" : \"Resistance is futile\",\n"
            + "  \"type\" : \"password\",\n"
            + "  \"additional_permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"bob\",\n"
            + "       \"operations\": [\"read\", \"read_acl\", \"write\"]\n"
            + "     }]"
            + "}")
        .accept(APPLICATION_JSON);

    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(edit)
        .andDo(print())
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void PUT_whenTheUserUpdatesOwnPermission_returnsBadRequest() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
            + "  \"value\" : \"Resistance is futile\",\n"
            + "  \"type\" : \"password\",\n"
            + "  \"additional_permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d\",\n"
            + "       \"operations\": [\"read\", \"read_acl\", \"write\"]\n"
            + "     }]"
            + "}")
        .accept(APPLICATION_JSON);

    String expectedError = "Modification of access control for the authenticated user is not allowed. Please contact an administrator.";

    this.mockMvc.perform(edit)
        .andDo(print())
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void POST_whenTheUserUpdatesOwnPermission_returnsBadRequest() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + "test-credential" + "\",\n"
            + "  \"type\": \"password\","
            + "  \"additional_permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    String expectedError = "Modification of access control for the authenticated user is not allowed. Please contact an administrator.";

    this.mockMvc.perform(post)
        .andDo(print())
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void POST_whenTheUserLacksPermissionToReadTheAcl_returnsAccessDenied() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + CREDENTIAL_NAME + "\",\n"
            + "  \"type\" : \"password\"\n"
            + "}")
        .accept(APPLICATION_JSON);

    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(edit)
        .andDo(print())
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void POST_whenTheUserHasPermissionToWriteAnAcl_succeeds() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
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
  public void POST_whenTheUserLacksPermissionToWriteAnAcl_returnsAccessDenied() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + SECOND_CREDENTIAL_NAME + "\",\n"
            + "  \"type\" : \"password\",\n"
            + "  \"additional_permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"bob\",\n"
            + "       \"operations\": [\"read\", \"read_acl\", \"write\"]\n"
            + "     }]"
            + "}")
        .accept(APPLICATION_JSON);

    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(edit)
        .andDo(print())
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void DELETE_whenTheUserHasPermissionToDeleteTheCredential_succeeds() throws Exception {
    final MockHttpServletRequestBuilder deleteRequest = delete("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(deleteRequest)
        .andExpect(status().isNoContent());

    final MockHttpServletRequestBuilder getRequest = get("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(getRequest)
        .andExpect(status().isNotFound());
  }

  @Test
  public void DELETE_whenTheUserLacksPermissionToDeleteTheCredential_returns404() throws Exception {
    final MockHttpServletRequestBuilder deleteRequest = delete("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    mockMvc.perform(deleteRequest)
        .andExpect(status().isNotFound());

    final MockHttpServletRequestBuilder getRequest = get("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(getRequest)
        .andExpect(status().isOk());
  }

  private void seedCredential() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + CREDENTIAL_NAME + "\",\n"
            + "  \"type\": \"password\","
            + "  \"additional_permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"uaa-client:credhub_test\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    final MvcResult result = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn();

    final MockHttpServletRequestBuilder otherPost = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + SECOND_CREDENTIAL_NAME + "\",\n"
            + "  \"type\": \"password\","
            + "  \"additional_permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"uaa-client:credhub_test\",\n"
            + "       \"operations\": [\"read\", \"read_acl\", \"write\"]\n"
            + "     }]"
            + "}");

    final MvcResult otherResult = mockMvc.perform(otherPost)
        .andExpect(status().isOk())
        .andReturn();

    result.getResponse().getContentAsString();
    final DocumentContext context = JsonPath.parse(result.getResponse().getContentAsString());
    uuid = context.read("$.id");
  }
}
