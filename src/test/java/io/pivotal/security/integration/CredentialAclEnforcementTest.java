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

  @Autowired
  WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private String uuid;
  private String credentialName = "/" + this.getClass().getName();

  @Before
  public void setup() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
    seedCredential();
  }

  @Test
  public void GET_byCredentialName_whenTheUserHasPermissionToReadCredential_returnsTheCredential() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + credentialName)
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].type", equalTo("password")))
        .andExpect(jsonPath("$.data[0].name", equalTo(credentialName)));
  }

  @Test
  public void GET_byCredentialName_whenTheUserDoesntHavePermissionToReadCredential_returns404() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + credentialName)
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
        .andExpect(jsonPath("$.name", equalTo(credentialName)));
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
  public void PUT_POST_whenTheUserLacksPermissionToReadTheAcl_returnsAccessDenied() throws Exception {
    // UAA_OAUTH2_PASSWORD_GRANT_TOKEN attempts to edit the credential
    final MockHttpServletRequestBuilder edit = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        // language=JSON
        .content("{\n"
            + "  \"name\" : \"" + credentialName + "\",\n"
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

  private void seedCredential() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + credentialName + "\",\n"
            + "  \"type\": \"password\","
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"uaa-client:credhub_test\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    final MvcResult result = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn();
    result.getResponse().getContentAsString();
    final DocumentContext context = JsonPath.parse(result.getResponse().getContentAsString());
    uuid = context.read("$.id");
  }
}
