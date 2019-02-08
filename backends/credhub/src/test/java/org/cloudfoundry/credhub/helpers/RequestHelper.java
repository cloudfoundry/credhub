package org.cloudfoundry.credhub.helpers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.views.PermissionsView;
import org.hamcrest.core.IsEqual;

import static java.lang.String.join;
import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
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
    super();
  }

  public static String setPassword(
    final MockMvc mockMvc, final String credentialName, final String passwordValue, final String token) throws Exception {
    final Map<String, Object> passwordRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "password");
        put("value", passwordValue);
      }
    };

    final String content = JsonTestHelper.serializeToString(passwordRequestBody);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String response;
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

  public static String generatePassword(final MockMvc mockMvc, final String credentialName, final boolean overwrite, final Integer length, final String token) throws Exception {
    final Map<String, Object> passwordRequestBody = new HashMap() {
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

    final String content = JsonTestHelper.serializeToString(passwordRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String response;
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

  public static String generateUser(
    final MockMvc mockMvc, final String credentialName, final boolean overwrite, final Integer length, final String username, final boolean excludeUpper)
    throws Exception {
    final Map<String, Object> userRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "user");
      }
    };

    if (overwrite) {
      userRequestBody.put("overwrite", true);
    }

    final Map parameters = new HashMap<String, Object>();

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

    final String content = JsonTestHelper.serializeToString(userRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateSsh(
    final MockMvc mockMvc, final String credentialName, final boolean overwrite, final Integer length, final String sshComment)
    throws Exception {
    final Map<String, Object> sshRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "ssh");
      }
    };

    if (overwrite) {
      sshRequestBody.put("overwrite", true);
    }

    final Map parameters = new HashMap<String, Object>();

    if (length != null) {
      parameters.put("key_length", length);
    }

    if (sshComment != null) {
      parameters.put("ssh_comment", sshComment);
    }

    sshRequestBody.put("parameters", parameters);
    final String content = JsonTestHelper.serializeToString(sshRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String getCertificateCredentials(final MockMvc mockMvc, final String token)
    throws Exception {

    final MockHttpServletRequestBuilder get = get("/api/v1/certificates")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String getCertificateCredentialsByName(final MockMvc mockMvc, final String token, final String name)
    throws Exception {

    final MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + name)
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String getCertificateId(final MockMvc mockMvc, final String certificateName) throws Exception {
    final String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, certificateName);
    return JsonPath.parse(response)
      .read("$.certificates[0].id");
  }

  public static String generateCertificateCredential(final MockMvc mockMvc, final String credentialName, final boolean overwrite, final String commonName, final String caName, final String token) throws Exception {
    final Map<String, Object> certRequestBody = new HashMap() {
      {
        put("name", credentialName);
        put("type", "certificate");
      }
    };

    if (overwrite) {
      certRequestBody.put("overwrite", true);
    }

    final Map parameters = new HashMap<String, Object>();
    if (caName == null) {
      parameters.put("self_sign", true);
      parameters.put("is_ca", true);
    } else {
      parameters.put("ca", caName);
    }
    parameters.put("common_name", commonName);


    certRequestBody.put("parameters", parameters);
    final String content = JsonTestHelper.serializeToString(certRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateRsa(
    final MockMvc mockMvc, final String credentialName, final boolean overwrite, final Integer length)
    throws Exception {
    final Map<String, Object> rsaRequestBody = new HashMap() {
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
    final String content = JsonTestHelper.serializeToString(rsaRequestBody);
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    final String response = mockMvc.perform(post)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return response;
  }

  public static String generateCa(final MockMvc mockMvc, final String caName, final String token) throws Exception {
    final MockHttpServletRequestBuilder caPost = post("/api/v1/data")
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

    final String caResult = mockMvc.perform(caPost)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();
    return caResult;
  }

  private static MockHttpServletRequestBuilder createRequestForGenerateCertificate(final String certName,
                                                                                   final String caName, final String token) {
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

  public static void generateCertificate(final MockMvc mockMvc, final String certName, final String caName,
                                         final String token) throws Exception {
    final MockHttpServletRequestBuilder certPost = createRequestForGenerateCertificate(certName, caName,
      token);

    mockMvc.perform(certPost)
      .andDo(print())
      .andExpect(status().isOk());
  }

  public static void expect404WhileGeneratingCertificate(final MockMvc mockMvc, final String certName,
                                                         final String token, final String expectedMessage) throws Exception {
    final MockHttpServletRequestBuilder certPost = post("/api/v1/data")
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

  public static void expect404WhileRegeneratingCertificate(final MockMvc mockMvc, final String certName,
                                                           final String token, final String message) throws Exception {
    final MockHttpServletRequestBuilder certPost = post("/api/v1/data")
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
    final MockMvc mockMvc,
    final String credentialName,
    final String grantorToken,
    final String granteeName,
    final String... permissions
  ) throws Exception {
    final MockHttpServletRequestBuilder post = createAddPermissionsRequest(
      grantorToken, credentialName, granteeName,
      permissions);

    mockMvc.perform(post)
      .andExpect(status().isCreated());
  }

  public static void expectErrorWhenAddingPermissions(
    final MockMvc mockMvc,
    final int status,
    final String message,
    final String credentialName,
    final String grantorToken,
    final String grantee,
    final String... permissions
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
    final MockMvc mockMvc,
    final String credentialName,
    final String requesterToken
  ) throws Exception {
    final String content = mockMvc.perform(get("/api/v1/permissions?credential_name=" + credentialName)
      .header("Authorization", "Bearer " + requesterToken))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andReturn()
      .getResponse()
      .getContentAsString();
    return JsonTestHelper.deserialize(content, PermissionsView.class);
  }

  public static void expectErrorWhenGettingPermissions(
    final MockMvc mockMvc,
    final int status,
    final String expectedErrorMessage,
    final String credentialName,
    final String requesterToken
  ) throws Exception {
    mockMvc.perform(get("/api/v1/permissions" +
      (credentialName == null ? "" : "?credential_name=" + credentialName))
      .header("Authorization", "Bearer " + requesterToken))
      .andExpect(status().is(status))
      .andExpect(jsonPath("$.error", equalTo(expectedErrorMessage)));
  }

  public static void revokePermissions(
    final MockMvc mockMvc,
    final String credentialName,
    final String grantorToken,
    final String grantee
  ) throws Exception {
    expectStatusWhenDeletingPermissions(mockMvc, 204, credentialName, grantee,
      grantorToken
    );
  }

  public static void expectStatusWhenDeletingPermissions(
    final MockMvc mockMvc,
    final int status, final String credentialName,
    final String grantee,
    final String grantorToken) throws Exception {
    expectErrorWhenDeletingPermissions(mockMvc, status, null, credentialName, grantorToken, grantee
    );
  }

  public static void expectErrorWhenDeletingPermissions(
    final MockMvc mockMvc,
    final int status,
    final String expectedErrorMessage,
    final String credentialName,
    final String grantorToken,
    final String grantee
  ) throws Exception {
    final ResultActions result = mockMvc.perform(
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

  private static MockHttpServletRequestBuilder createAddPermissionsRequest(final String grantorToken,
                                                                           final String credentialName,
                                                                           final String grantee, final String... permissions) {
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

  public static String regenerateCertificate(
    final MockMvc mockMvc, final String uuid, final boolean transitional, final String token) throws Exception {
    final MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + uuid + "/regenerate")
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
