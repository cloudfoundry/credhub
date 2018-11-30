package org.cloudfoundry.credhub.helper;

import java.util.HashMap;
import java.util.Map;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.view.PermissionsView;
import org.hamcrest.core.IsEqual;

import static java.lang.String.join;
import static org.cloudfoundry.credhub.util.AuthConstants.ALL_PERMISSIONS_TOKEN;
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

final public class RequestHelper {

  private RequestHelper() {
  }

  public static String setPassword(MockMvc mockMvc, String credentialName, String passwordValue, String token) throws Exception {
    Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "password");
        put("value", passwordValue);
      }
    };

    String content = JsonTestHelper.serializeToString(passwordRequestBody);

    MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    String response;
    if (credentialName.length() <= 1024) {
      response = mockMvc.perform(put)
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn().getResponse().getContentAsString();
    } else {
      response = mockMvc.perform(put)
        .andExpect(status().isBadRequest())
        .andDo(print())
        .andReturn().getResponse().getContentAsString();
    }

    return response;
  }

  public static String generatePassword(MockMvc mockMvc, String credentialName, boolean overwrite, Integer length, String token) throws Exception {
    Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "password");
      }
    };

    if (overwrite) {
      passwordRequestBody.put("overwrite", true);
    }

    if (length != null) {
      passwordRequestBody.put("parameters", ImmutableMap.of("length", length));
    }

    String content = JsonTestHelper.serializeToString(passwordRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    String response;
    if (credentialName.length() <= 1024) {
      response = mockMvc.perform(post)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    } else {
      response = mockMvc.perform(post)
        .andExpect(status().isBadRequest())
        .andReturn().getResponse().getContentAsString();
    }
    return response;
  }

  public static String generateUser(MockMvc mockMvc, String credentialName, boolean overwrite, Integer length, String username, boolean excludeUpper)
    throws Exception {
    Map<String, Object> userRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "user");
      }
    };

    if (overwrite) {
      userRequestBody.put("overwrite", true);
    }

    Map parameters = new HashMap<String, Object>();

    if (length != null) {
      parameters.put("length", length);
    }

    if (username != null) {
      parameters.put("username", username);
    }

    if (excludeUpper) {
      parameters.put("exclude_upper", true);
    }

    userRequestBody.put("parameters", parameters);

    String content = JsonTestHelper.serializeToString(userRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateSsh(MockMvc mockMvc, String credentialName, boolean overwrite, Integer length, String sshComment)
    throws Exception {
    Map<String, Object> sshRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "ssh");
      }
    };

    if (overwrite) {
      sshRequestBody.put("overwrite", true);
    }

    Map parameters = new HashMap<String, Object>();

    if (length != null) {
      parameters.put("key_length", length);
    }

    if (sshComment != null) {
      parameters.put("ssh_comment", sshComment);
    }

    sshRequestBody.put("parameters", parameters);
    String content = JsonTestHelper.serializeToString(sshRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String getCertificateCredentials(MockMvc mockMvc, String token)
    throws Exception {

    MockHttpServletRequestBuilder get = get("/api/v1/certificates")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String getCertificateCredentialsByName(MockMvc mockMvc, String token, String name)
    throws Exception {

    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + name)
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String getCertificateId(MockMvc mockMvc, String certificateName) throws Exception {
    String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, certificateName);
    return JsonPath.parse(response)
      .read("$.certificates[0].id");
  }

  public static String generateCertificateCredential(MockMvc mockMvc, String credentialName, boolean overwrite, String commonName, String caName, String token) throws Exception {
    Map<String, Object> certRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "certificate");
      }
    };

    if (overwrite) {
      certRequestBody.put("overwrite", true);
    }

    Map parameters = new HashMap<String, Object>();
    if (caName == null) {
      parameters.put("self_sign", true);
      parameters.put("is_ca", true);
    } else {
      parameters.put("ca", caName);
    }
    parameters.put("common_name", commonName);


    certRequestBody.put("parameters", parameters);
    String content = JsonTestHelper.serializeToString(certRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateRsa(MockMvc mockMvc, String credentialName, boolean overwrite, Integer length)
    throws Exception {
    Map<String, Object> rsaRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "rsa");
      }
    };

    if (overwrite) {
      rsaRequestBody.put("overwrite", true);
    }

    if (length != null) {
      rsaRequestBody.put("parameters", ImmutableMap.of("key_length", length));
    }
    String content = JsonTestHelper.serializeToString(rsaRequestBody);
    MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
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
        + "  \"overwrite\": true,\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true\n"
        + "  }\n"
        + "}");

    String caResult = mockMvc.perform(caPost)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return caResult;
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
        + "       \"path\": \"" + credentialName + "\",\n"
        + "       \"operations\": [\"" + join("\", \"", permissions) + "\"]\n"
        + "     }]"
        + "}");
  }

  public static String regenerateCertificate(MockMvc mockMvc, String uuid, boolean transitional, String token) throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + uuid + "/regenerate")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\"set_as_transitional\" : " + transitional + "}");

    return mockMvc.perform(regenerateRequest)
      .andExpect(status().is2xxSuccessful())
      .andReturn().getResponse().getContentAsString();
  }
}
