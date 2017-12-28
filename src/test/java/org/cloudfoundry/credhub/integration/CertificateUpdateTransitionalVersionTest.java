package org.cloudfoundry.credhub.integration;


import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.json.JSONArray;
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

import static org.cloudfoundry.credhub.helper.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CertificateUpdateTransitionalVersionTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;

  private AuditingHelper auditingHelper;
  private Object caCertificate;
  private String caName = "/some-ca";
  private String caCredentialUuid;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    final String generateCaResponse = generateCa(mockMvc, caName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    caCertificate = JsonPath.parse(generateCaResponse)
        .read("$.value.certificate");
    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, caName);
    caCredentialUuid = JsonPath.parse(response)
        .read("$.certificates[0].id");
    assertNotNull(caCertificate);

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void certificateUpdateTransitionalVersion_changesValueOfTransitionalFlag() throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"set_as_transitional\": true" +
            "}");

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.transitional", equalTo(true)));

    MockHttpServletRequestBuilder versionsRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String versionsResponse = this.mockMvc.perform(versionsRequest)
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

    String originalVersion = new JSONArray(versionsResponse).get(1).toString();
    String regeneratedVersion = new JSONArray(versionsResponse).get(0).toString();

    assertThat(JsonPath.parse(regeneratedVersion).read("transitional"), equalTo(true));
    String originalVersionId = JsonPath.parse(originalVersion).read("id");

    MockHttpServletRequestBuilder updateTransitionalRequest = put(
        "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"version\": \"" + originalVersionId + "\"" +
            "}");

    this.mockMvc.perform(updateTransitionalRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].transitional", equalTo(false)))
        .andExpect(jsonPath("$[1].transitional", equalTo(true)))
        .andExpect(jsonPath("$[1].id", equalTo(originalVersionId)));

    auditingHelper.verifyAuditing(AuditingOperationCode.CREDENTIAL_UPDATE, caName, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version", 200);
  }

  @Test
  public void certificateUpdateTransitionalVersion_whenThereIsNoExistingTransitionalVersion_changesValueOfTransitionalFlag()
      throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.transitional", equalTo(false)));

    MockHttpServletRequestBuilder versionsRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String versionsResponse = this.mockMvc.perform(versionsRequest)
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

    String originalVersion = new JSONArray(versionsResponse).get(1).toString();
    String originalVersionId = JsonPath.parse(originalVersion).read("id");

    MockHttpServletRequestBuilder updateTransitionalRequest = put(
        "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"version\": \"" + originalVersionId + "\"" +
            "}");

    this.mockMvc.perform(updateTransitionalRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].transitional", equalTo(false)))
        .andExpect(jsonPath("$[1].transitional", equalTo(true)))
        .andExpect(jsonPath("$[1].id", equalTo(originalVersionId)));

    auditingHelper.verifyAuditing(AuditingOperationCode.CREDENTIAL_UPDATE, caName, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version", 200);
  }

  @Test
  public void certificateUpdateTransitionalVersion_whenNoVersionIdIsProvided_unSetsTransitionalFlag() throws Exception {
    MockHttpServletRequestBuilder regenerateRequest = post("/api/v1/certificates/" + caCredentialUuid + "/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    this.mockMvc.perform(regenerateRequest)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.transitional", equalTo(false)));

    MockHttpServletRequestBuilder versionsRequest = get("/api/v1/certificates/" + caCredentialUuid + "/versions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String versionsResponse = this.mockMvc.perform(versionsRequest)
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

    String regeneratedVersion = new JSONArray(versionsResponse).get(0).toString();
    String regeneratedVersionId = JsonPath.parse(regeneratedVersion).read("id");

    MockHttpServletRequestBuilder updateTransitionalRequest = put(
        "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{}");

    this.mockMvc.perform(updateTransitionalRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].transitional", equalTo(false)))
        .andExpect(jsonPath("$[0].id", equalTo(regeneratedVersionId)));

    auditingHelper.verifyAuditing(AuditingOperationCode.CREDENTIAL_UPDATE, caName, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/certificates/" + caCredentialUuid + "/update_transitional_version", 200);
  }
}

