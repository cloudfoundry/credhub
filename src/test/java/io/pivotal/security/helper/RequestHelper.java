package io.pivotal.security.helper;

import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsEqual;
import org.json.JSONObject;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class RequestHelper {
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

  private static MockHttpServletRequestBuilder createRequestForGenerateCertificate(String certName, String caName, String token) {
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

  public static void generateCertificate(MockMvc mockMvc, String certName, String caName, String token) throws Exception {
    MockHttpServletRequestBuilder certPost = createRequestForGenerateCertificate(certName, caName, token);

    mockMvc.perform(certPost)
        .andDo(print())
        .andExpect(status().isOk());
  }

  public static void grantPermission(MockMvc mockMvc, String grantorToken, String granteeName, String permissionType, String credentialName) throws Exception {
    MockHttpServletRequestBuilder permissionAdd = post("/api/v1/permissions")
        .header("Authorization", "Bearer " + grantorToken)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n" +
            "  \"credential_name\": \"" + credentialName + "\",\n" +
            "  \"permissions\": [ {\n" +
            "      \"actor\": \"" + granteeName + "\",\n" +
            "      \"operations\": [\"" + permissionType + "\"]\n" +
            "  } ]\n" +
            "}");
    mockMvc.perform(permissionAdd)
        .andDo(print())
        .andExpect(status().isOk());
  }

  public static void revokePermissions(MockMvc mockMvc, String grantorToken, String granteeName, String credentialName) throws Exception {
    String urlString = "/api/v1/permissions?" +
        "credential_name=" + credentialName +
        "&actor=" + granteeName;
    MockHttpServletRequestBuilder permissionAdd = delete(urlString)
        .header("Authorization", "Bearer " + grantorToken)
        .contentType(APPLICATION_JSON);

    mockMvc.perform(permissionAdd)
        .andDo(print())
        .andExpect(status().isNoContent());
  }

  public static void expect404WhileGeneratingCertificate(MockMvc mockMvc, String certName, String token, String expectedMessage) throws Exception {
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

  public static void expect404WhileRegeneratingCertificate(MockMvc mockMvc, String certName, String token, String message) throws Exception {
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
}
