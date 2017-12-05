package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
public class RegenerationEndpointTest {

  private static final String API_V1_DATA_ENDPOINT = "/api/v1/data";
  private static final String API_V1_REGENERATE_ENDPOINT = "/api/v1/regenerate";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;
  private String originalPassword;
  private AuditingHelper auditingHelper;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);

    MockHttpServletRequestBuilder generatePasswordRequest = post(API_V1_DATA_ENDPOINT)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"picard\",\n"
            + "  \"type\" : \"password\",\n"
            + "  \"additional_permissions\":\n"
            + "  [\n"
            + "    {\n"
            + "      \"actor\": \" " + AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID + "\",\n"
            + "      \"operations\": [\"write\", \"read\"]\n"
            + "    }\n"
            + "  ]\n"
            + "}");

    String generatePasswordResult = this.mockMvc.perform(generatePasswordRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    originalPassword = (new JSONObject(generatePasswordResult)).getString("value");
    assertThat(originalPassword, notNullValue());
  }

  @Test
  public void passwordRegeneration_withDefaultParameters_shouldRegeneratePassword() throws Exception {
    MockHttpServletRequestBuilder regeneratePasswordRequest = post(API_V1_REGENERATE_ENDPOINT)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"picard\"\n"
            + "}");

    String regeneratePasswordResult = this.mockMvc.perform(regeneratePasswordRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    String regeneratedPassword = (new JSONObject(regeneratePasswordResult)).getString("value");

    assertThat(regeneratedPassword, notNullValue());
    assertThat(regeneratedPassword, not(equalTo(originalPassword)));
  }

  @Test
  public void regenerating_PersistsAnAuditEntry() throws Exception {
    MockHttpServletRequestBuilder request = post(API_V1_REGENERATE_ENDPOINT)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\": \"picard\"\n"
            + "}");

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.type").value("password"));

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/picard", AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, API_V1_REGENERATE_ENDPOINT, 200);
  }

  @Test
  public void passwordRegeneration_withoutWritePermissionShouldFail() throws Exception {
    MockHttpServletRequestBuilder regeneratePasswordRequest = post(API_V1_REGENERATE_ENDPOINT)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" : \"picard\"\n"
            + "}");

    this.mockMvc.perform(regeneratePasswordRequest)
        .andDo(print())
        .andExpect(status().isForbidden());
  }
}
