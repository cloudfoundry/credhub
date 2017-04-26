package io.pivotal.security.integration;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.helper.AuditingHelper.verifyAuditing;
import static io.pivotal.security.helper.AuditingHelper.verifyRequestAuditing;
import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
public class AccessControlEndpointTest {

  @Autowired
  private WebApplicationContext webApplicationContext;
  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;
  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"/cred1\","
            + "  \"type\": \"password\","
            + "  \"value\": \"testpassword\""
            + "}");

    this.mockMvc.perform(put)
        .andExpect(status().isOk());
  }

  @Test
  public void GET_whenTheCredentialNameParaemterIsMissing_returnsAnAppropriateError() throws Exception {
    MockHttpServletRequestBuilder getRequest = get(
        "/api/v1/acls")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(getRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The query parameter credential_name is required for this request.")));
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessTheACL_returnsTheFullACL() throws Exception {
    seedCredential();

    MvcResult result = mockMvc.perform(
        get("/api/v1/acls?credential_name=/cred1")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    AccessControlListResponse acl = JsonHelper
        .deserialize(content, AccessControlListResponse.class);
    assertThat(acl.getCredentialName(), equalTo("/cred1"));
    assertThat(acl.getAccessControlList(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ)))
    ));

    verifyAudit(ACL_ACCESS, "/cred1", 200);
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessTheACL_andTheLeadingSlashIsMissing_returnsTheFullACL() throws Exception {
    seedCredential();

    MvcResult result = mockMvc.perform(
        get("/api/v1/acls?credential_name=cred1")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
    assertThat(acl.getCredentialName(), equalTo("/cred1"));
    assertThat(acl.getAccessControlList(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ)))
    ));

    verifyAudit(ACL_ACCESS, "/cred1", 200);
  }

  @Test
  @Ignore("ACL enforcement is disabled in tests")
  public void GET_whenTheUserLacksPermissionToReadTheAcl_returnsNotFound() throws Exception {
    // Credential was created with UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred1")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON);

    String expectedError = "The request could not be fulfilled because the resource could not be found.";
    this.mockMvc.perform(get)
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error", equalTo(
            expectedError)));
  }

  @Test
  public void GET_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    mockMvc.perform(
        get("/api/v1/acls?credential_name=/unicorn")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    ).andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error", equalTo(
            "The request could not be fulfilled "
                + "because the resource could not be found.")));

    verifyAudit(ACL_ACCESS, "/unicorn", 404);
  }

  @Test
  public void DELETE_whenTheCredentialParameterNameIsMissing_returnsBadRequest() throws Exception {
    MockHttpServletRequestBuilder deleteRequest = delete(
        "/api/v1/aces?actor=dan")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(deleteRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The query parameter credential_name is required for this request.")));

    verifyRequestAuditing(
        requestAuditRecordRepository,
        "/api/v1/aces",
        400
    );
  }

  @Test
  public void DELETE_whenTheActorParameterIsMissing_returnsBadRequest() throws Exception {
    MockHttpServletRequestBuilder deleteRequest = delete(
        "/api/v1/aces?credential_name=octopus")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(deleteRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The query parameter actor is required for this request.")));

    verifyRequestAuditing(
        requestAuditRecordRepository,
        "/api/v1/aces",
        400
    );
  }

  @Test
  public void DELETE_whenTheActorIsAllowedToDeleteACEs_shouldDeleteTheSpecifiedACE() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"/cred1\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    mockMvc.perform(post)
        .andExpect(status().isOk());

    mockMvc.perform(
        get("/api/v1/acls?credential_name=cred1")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.access_control_list").isNotEmpty());

    mockMvc.perform(
        delete("/api/v1/aces?credential_name=/cred1&actor=dan")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isNoContent());

    verifyEntryAudit(AuditingOperationCode.ACL_DELETE, "/cred1", 204);
    mockMvc.perform(
        get("/api/v1/acls?credential_name=/cred1")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.access_control_list", hasSize(1)));
  }

  @Test
  public void DELETE_whenTheCredentialDoesntExist_shouldReturnNotFound() throws Exception {
    mockMvc.perform(
        delete("/api/v1/aces?credential_name=/not-valid&actor=something")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error").value(
            "The request could not be fulfilled because the resource could not be found."));

    verifyRequestAuditing(
        requestAuditRecordRepository,
        "/api/v1/aces",
        404
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWriteACEs_returnsTheACL() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"/cred1\","
            + "  \"access_control_entries\": ["
            + "     {"
            + "       \"actor\": \"dan\","
            + "       \"operations\": [\"read\",\"write\"]"
            + "     },"
            + "     {"
            + "       \"actor\": \"isobel\","
            + "       \"operations\": [\"delete\"]"
            + "     }" +
            "]"
            + "}");

    MvcResult result = this.mockMvc.perform(post).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
    assertThat(acl.getAccessControlList(), hasSize(3));
    assertThat(acl.getCredentialName(), equalTo("/cred1"));
    assertThat(acl.getAccessControlList(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ, WRITE))),
        samePropertyValuesAs(
            new AccessControlEntry("isobel", asList(DELETE)))
    ));

    verifyAuditing(
        requestAuditRecordRepository,
        eventAuditRecordRepository,
        "/api/v1/aces",
        200,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, "/cred1", READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, "/cred1", WRITE, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, "/cred1", DELETE, "isobel")
        )
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWriteACEs_updatesTheACL() throws Exception {
    final MockHttpServletRequestBuilder initialPost = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"/cred1\","
            + "  \"access_control_entries\": ["
            + "     {"
            + "       \"actor\": \"dan\","
            + "       \"operations\": [\"read\",\"delete\"]"
            + "     }]"
            + "}");
    mockMvc.perform(initialPost)
        .andExpect(status().isOk());

    final MockHttpServletRequestBuilder updatePost = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"/cred1\","
            + "  \"access_control_entries\": ["
            + "     {"
            + "       \"actor\": \"dan\","
            + "       \"operations\": [\"write\",\"read\"]"
            + "     }]"
            + "}");

    MvcResult result = this.mockMvc.perform(updatePost).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
    assertThat(acl.getAccessControlList(), hasSize(2));
    assertThat(acl.getCredentialName(), equalTo("/cred1"));
    assertThat(acl.getAccessControlList(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ, WRITE, DELETE)))
    ));

    // 1 from beforeEach for credential, 2 from initialPost, 2 from updatePost
    assertThat(eventAuditRecordRepository.count(), equalTo(5L));

    verifyAuditing(
        requestAuditRecordRepository,
        eventAuditRecordRepository,
        "/api/v1/aces",
        200,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, "/cred1", READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, "/cred1", WRITE, "dan")
        )
    );
  }

  @Test
  public void POST_whenTheLeadingSlashIsMissing_prependsTheSlashCorrectly() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"cred1\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    MvcResult result = this.mockMvc.perform(post).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
    assertThat(acl.getCredentialName(), equalTo("/cred1"));
    assertThat(acl.getAccessControlList(), hasSize(2));
    assertThat(acl.getAccessControlList(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", singletonList(READ)))
    ));

    verifyAuditing(
        requestAuditRecordRepository,
        eventAuditRecordRepository,
        "/api/v1/aces",
        200,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, "/cred1", READ, "dan")
        )
    );
  }

  @Test
  public void POST_whenMalformedJsonIsSent_returnsBadRequest() throws Exception {
    final String malformedJson = "{"
        + "  \"credential_name\": \"foo\","
        + "  \"access_control_entries\": ["
        + "     {"
        + "       \"actor\": \"dan\","
        + "       \"operations\":"
        + "     }]"
        + "}";
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(malformedJson);

    this.mockMvc.perform(post).andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error", equalTo(
            "The request could not be fulfilled because the request path or body did"
                + " not meet expectation. Please check the documentation for required "
                + "formatting and retry your request.")));

    verifyRequestAuditing(
        requestAuditRecordRepository,
        "/api/v1/aces",
        400
    );
  }

  @Test
  public void POST_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"/this-is-a-fake-credential\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    this.mockMvc.perform(post).andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error", equalTo(
            "The request could not be fulfilled because the resource could not be found.")));

    verifyAuditing(
        requestAuditRecordRepository,
        eventAuditRecordRepository,
        "/api/v1/aces",
        404,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, "/this-is-a-fake-credential", READ, "dan")
        )
    );
  }

  @Test
  public void POST_withAnInvalidOperation_returnsBadRequest() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"cred1\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"unicorn\"]\n"
            + "     }]"
            + "}");

    this.mockMvc.perform(post).andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(
            "The provided operation is not supported."
                + " Valid values include read, write, delete, read_acl, and write_acl."));

    verifyRequestAuditing(
        requestAuditRecordRepository,
        "/api/v1/aces",
        400
    );
  }

  private void verifyAudit(AuditingOperationCode operation, String credentialName, int statusCode) {
    verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, operation, credentialName, "/api/v1/acls", statusCode);
  }

  private void verifyEntryAudit(AuditingOperationCode operation, String credentialName, int statusCode) {
    verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, operation, credentialName, "/api/v1/aces", statusCode);
  }

  private void seedCredential() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"/cred1\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    this.mockMvc.perform(post)
        .andExpect(status().isOk());
  }
}
