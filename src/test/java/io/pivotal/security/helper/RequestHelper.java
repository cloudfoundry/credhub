package io.pivotal.security.helper;

import com.google.common.collect.ImmutableMap;
import io.pivotal.security.view.PermissionsView;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsEqual;
import org.json.JSONObject;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.HashMap;
import java.util.Map;

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.lang.String.join;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class RequestHelper {

  public static void setPassword(MockMvc mockMvc, String credentialName, String passwordValue)
      throws Exception {
    MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + credentialName + "\","
            + "  \"type\": \"password\","
            + "  \"value\": \"" + passwordValue + "\""
            + "}");

    mockMvc.perform(put)
        .andExpect(status().isOk());
  }

  public static String generatePassword(MockMvc mockMvc, String credentialName, String mode, Integer length)
      throws Exception {
    Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "password");
        put("mode", mode);
      }
    };

    if (length != null) {
      passwordRequestBody.put("parameters", ImmutableMap.of("length", length));
    }
    String content = JsonTestHelper.serializeToString(passwordRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    String response = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateUser(MockMvc mockMvc, String credentialName, String mode, Integer length)
      throws Exception {
    Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "user");
        put("mode", mode);
      }
    };

    if (length != null) {
      passwordRequestBody.put("parameters", ImmutableMap.of("length", length));
    }
    String content = JsonTestHelper.serializeToString(passwordRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    String response = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateSsh(MockMvc mockMvc, String credentialName, String mode, Integer length)
      throws Exception {
    Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "ssh");
        put("mode", mode);
      }
    };

    if (length != null) {
      passwordRequestBody.put("parameters", ImmutableMap.of("key_length", length));
    }
    String content = JsonTestHelper.serializeToString(passwordRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    String response = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateRsa(MockMvc mockMvc, String credentialName, String mode, Integer length)
      throws Exception {
    Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "rsa");
        put("mode", mode);
      }
    };

    if (length != null) {
      passwordRequestBody.put("parameters", ImmutableMap.of("key_length", length));
    }
    String content = JsonTestHelper.serializeToString(passwordRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(content);

    String response = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateCa(MockMvc mockMvc, String caName, String token) throws Exception {
    MockHttpServletRequestBuilder caPost = post("/api/v1/data")
        .header("Authorization", "Bearer " + token)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"" + caName + "\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"is_ca\" : true,\n"
            + "    \"self_sign\" : true\n"
            + "  }\n"
            + "}");

    String caResult = mockMvc.perform(caPost)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    String ca = new JSONObject(caResult)
        .getJSONObject("value")
        .getString("certificate");
    MatcherAssert.assertThat(ca, notNullValue());
    return ca;
  }

  private static MockHttpServletRequestBuilder createRequestForGenerateCertificate(String certName,
      String caName, String token) {
    return post("/api/v1/data")
        .header("Authorization", "Bearer " + token)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"" + certName + "\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"ca\" : \"" + caName + "\"\n"
            + "  }\n"
            + "}");
  }

  public static void generateCertificate(MockMvc mockMvc, String certName, String caName,
      String token) throws Exception {
    MockHttpServletRequestBuilder certPost = createRequestForGenerateCertificate(certName, caName,
        token);

    mockMvc.perform(certPost)
        .andDo(print())
        .andExpect(status().isOk());
  }

  public static void expect404WhileGeneratingCertificate(MockMvc mockMvc, String certName,
      String token, String expectedMessage) throws Exception {
    MockHttpServletRequestBuilder certPost = post("/api/v1/data")
        .header("Authorization", "Bearer " + token)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"" + certName + "\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"ca\" : \"picard\"\n"
            + "  }\n"
            + "}");

    mockMvc.perform(certPost)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error", equalTo(expectedMessage)));

  }

  public static void expect404WhileRegeneratingCertificate(MockMvc mockMvc, String certName,
      String token, String message) throws Exception {
    MockHttpServletRequestBuilder certPost = post("/api/v1/data")
        .header("Authorization", "Bearer " + token)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\"regenerate\":true,\"name\":\"" + certName + "\"}");

    mockMvc.perform(certPost)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error", IsEqual.equalTo(message)));
  }

  public static void grantPermissions(
      MockMvc mockMvc,
      String credentialName,
      String grantorToken,
      String granteeName,
      String... permissions
  ) throws Exception {
    final MockHttpServletRequestBuilder post = createAddPermissionsRequest(
        grantorToken, credentialName, granteeName,
        permissions);

    mockMvc.perform(post)
        .andExpect(status().isCreated());
  }

  public static void expectErrorWhenAddingPermissions(
      MockMvc mockMvc,
      int status,
      String message,
      String credentialName,
      String grantorToken,
      String grantee,
      String... permissions
  ) throws Exception {
    final MockHttpServletRequestBuilder post = createAddPermissionsRequest(
        grantorToken, credentialName, grantee,
        permissions);

    mockMvc.perform(post)
        .andExpect(status().is(status))
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(message));
  }

  public static PermissionsView getPermissions(
      MockMvc mockMvc,
      String credentialName,
      String requesterToken
  ) throws Exception {
    String content = mockMvc.perform(get("/api/v1/permissions?credential_name=" + credentialName)
        .header("Authorization", "Bearer " + requesterToken))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andReturn()
        .getResponse()
        .getContentAsString();
    return JsonTestHelper.deserialize(content, PermissionsView.class);
  }

  public static void expectErrorWhenGettingPermissions(
      MockMvc mockMvc,
      int status,
      String expectedErrorMessage,
      String credentialName,
      String requesterToken
  ) throws Exception {
    mockMvc.perform(get("/api/v1/permissions" +
        (credentialName == null ? "" : "?credential_name=" + credentialName))
        .header("Authorization", "Bearer " + requesterToken))
        .andExpect(status().is(status))
        .andExpect(jsonPath("$.error", equalTo(expectedErrorMessage)));
  }

  public static void revokePermissions(
      MockMvc mockMvc,
      String credentialName,
      String grantorToken,
      String grantee
  ) throws Exception {
    expectStatusWhenDeletingPermissions(mockMvc, 204, credentialName, grantee,
        grantorToken
    );
  }

  public static void expectStatusWhenDeletingPermissions(
      MockMvc mockMvc,
      int status, String credentialName,
      String grantee,
      String grantorToken) throws Exception {
    expectErrorWhenDeletingPermissions(mockMvc, status, null, credentialName, grantorToken, grantee
    );
  }

  public static void expectErrorWhenDeletingPermissions(
      MockMvc mockMvc,
      int status,
      String expectedErrorMessage,
      String credentialName,
      String grantorToken,
      String grantee
  ) throws Exception {
    ResultActions result = mockMvc.perform(
        delete("/api/v1/permissions?" +
            (credentialName == null ? "" : "credential_name=" + credentialName) +
            (grantee == null ? "" : "&actor=" + grantee)
        ).header("Authorization", "Bearer " + grantorToken)
    );
    result.andExpect(status().is(status));

    if (expectedErrorMessage != null) {
      result.andExpect(jsonPath("$.error", equalTo(expectedErrorMessage)));
    }
  }

  private static MockHttpServletRequestBuilder createAddPermissionsRequest(String grantorToken,
      String credentialName,
      String grantee, String... permissions) {
    return post("/api/v1/permissions")
        .header("Authorization", "Bearer " + grantorToken)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"" + credentialName + "\",\n"
            + "  \"permissions\": [\n"
            + "     { \n"
            + "       \"actor\": \"" + grantee + "\",\n"
            + "       \"operations\": [\"" + join("\", \"", permissions) + "\"]\n"
            + "     }]"
            + "}");
  }
}
