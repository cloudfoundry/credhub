package io.pivotal.security.integration;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import net.minidev.json.JSONObject;
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

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.TestConstants.TEST_CERTIFICATE;
import static io.pivotal.security.util.TestConstants.TEST_PRIVATE_KEY;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CertificateSetAndRegenerateTest {
  private static final String CA_NAME = "/picard";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private Object caCertificate;
  private String caId;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    MockHttpServletRequestBuilder generateCaRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" :\"" + CA_NAME + "\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"parameters\" : {\n"
            + "    \"common_name\" : \"federation\",\n"
            + "    \"is_ca\" : true,\n"
            + "    \"self_sign\" : true\n"
            + "  }\n"
            + "}");

    final String generateCaResponse = this.mockMvc
        .perform(generateCaRequest)
        .andExpect(status().isOk())
        .andReturn().getResponse()
        .getContentAsString();

    caCertificate = JsonPath.parse(generateCaResponse)
        .read("$.value.certificate");
    caId = JsonPath.parse(generateCaResponse).read("$.id");
    assertNotNull(caCertificate);
  }

  @Test
  public void certificateSet_withCaName_canBeRegeneratedWithSameCA() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", CA_NAME)
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    MockHttpServletRequestBuilder certificateSetRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"/crusher\",\n"
            + "  \"type\" : \"certificate\",\n"
            + "  \"value\" : " + setJson + "}");

    this.mockMvc.perform(certificateSetRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.value.ca", equalTo(caCertificate)));

    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"/crusher\"," +
            "\"regenerate\":true" +
          "}");

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.value.ca", equalTo(caCertificate)));
  }

  @Test
  public void certificateRegenerate_withTransitionalSetToTrue_generatesANewTransitionalCertificate() throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caId + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"transitional\": true" +
            "}");

    this.mockMvc.perform(regenerateRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.value.transitional", equalTo(true)));
  }
}
