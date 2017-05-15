package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.repository.CredentialRepository;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.PermissionsView;
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

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
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

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
public class PermissionsEndpointTest {

  @Autowired
  private WebApplicationContext webApplicationContext;
  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;
  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;
  @Autowired
  private CredentialRepository repository;

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;
  private String credentialNameWithoutLeadingSlash = this.getClass().getName();
  private String credentialName = "/" + credentialNameWithoutLeadingSlash;

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
            + "  \"name\": \"" + credentialName + "\","
            + "  \"type\": \"password\","
            + "  \"value\": \"testpassword\""
            + "}");

    this.mockMvc.perform(put)
        .andExpect(status().isOk());

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void GET_whenTheCredentialNameParameterIsMissing_returnsAnAppropriateError() throws Exception {
    MockHttpServletRequestBuilder getRequest = get(
        "/api/v1/permissions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    mockMvc.perform(getRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo("The query parameter credential_name is required for this request.")));
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessTheACL_returnsTheFullACL() throws Exception {
    seedCredential();

    MvcResult result = mockMvc.perform(
        get("/api/v1/permissions?credential_name=" + credentialName)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ)))
    ));

    verifyAudit(ACL_ACCESS, credentialName, 200);
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessTheACL_andTheLeadingSlashIsMissing_returnsTheFullACL() throws Exception {
    seedCredential();

    MvcResult result = mockMvc.perform(
        get("/api/v1/permissions?credential_name=" + credentialNameWithoutLeadingSlash)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isOk())
        .andDo(print())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonHelper.deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ)))
    ));

    verifyAudit(ACL_ACCESS, credentialName, 200);
  }

  @Test
  public void GET_whenTheUserLacksPermissionToReadTheAcl_returnsNotFound() throws Exception {
    // Credential was created with UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    final MockHttpServletRequestBuilder get = get("/api/v1/permissions?credential_name=" + credentialName)
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
        get("/api/v1/permissions?credential_name=/unicorn")
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

    auditingHelper.verifyRequestAuditing(
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

    auditingHelper.verifyRequestAuditing(
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
            + "  \"credential_name\": \"" + credentialName + "\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    mockMvc.perform(post)
        .andExpect(status().isOk());

    mockMvc.perform(
        delete("/api/v1/aces?credential_name=" + credentialName + "&actor=dan")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isNoContent());

    auditingHelper.verifyAuditing(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
        "/api/v1/aces",
        204,
        newArrayList(new EventAuditRecordParameters(ACL_DELETE, credentialName, READ, "dan"))
    );

    mockMvc.perform(
        get("/api/v1/permissions?credential_name=" + credentialName)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.permissions", hasSize(1)));
  }

  @Test
  public void DELETE_whenTheActorDoesNotHavePermissionToDeleteACEs_returnsNotFound() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"" + credentialName + "\",\n"
            + "  \"access_control_entries\": [\n"
            + "     { \n"
            + "       \"actor\": \"dan\",\n"
            + "       \"operations\": [\"read\"]\n"
            + "     }]"
            + "}");

    mockMvc.perform(post)
        .andExpect(status().isOk());

    mockMvc.perform(
        delete("/api/v1/aces?credential_name=" + credentialName + "&actor=dan")
            .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
    )
        .andExpect(status().isNotFound());

    auditingHelper.verifyAuditing(
        "uaa-client:credhub_test",
        "/api/v1/aces",
        404,
        newArrayList(new EventAuditRecordParameters(ACL_DELETE, credentialName, READ, "dan"))
    );

    mockMvc.perform(
        get("/api/v1/permissions?credential_name=" + credentialName)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.permissions", hasSize(2)));
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_shouldReturnNotFound() throws Exception {
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    mockMvc.perform(
        delete("/api/v1/aces?credential_name=/not-valid&actor=something")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error").value(
            expectedError));

    auditingHelper.verifyRequestAuditing(
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
            + "  \"credential_name\": \"" + credentialName + "\","
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
    PermissionsView acl = JsonHelper.deserialize(content, PermissionsView.class);
    assertThat(acl.getPermissions(), hasSize(3));
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ, WRITE))),
        samePropertyValuesAs(
            new AccessControlEntry("isobel", asList(DELETE)))
    ));

    auditingHelper.verifyAuditing(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
        "/api/v1/aces",
        200,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, DELETE, "isobel")
        )
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWriteACEs_updatesTheACL() throws Exception {
    Long initialCount = eventAuditRecordRepository.count();
    final MockHttpServletRequestBuilder initialPost = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"" + credentialName + "\","
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
            + "  \"credential_name\": \"" + credentialName + "\","
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
    PermissionsView acl = JsonHelper.deserialize(content, PermissionsView.class);
    assertThat(acl.getPermissions(), hasSize(2));
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", asList(READ, WRITE, DELETE)))
    ));

    // 2 from initialPost, 2 from updatePost
    assertThat(eventAuditRecordRepository.count(), equalTo(4L + initialCount));

    auditingHelper.verifyAuditing(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
        "/api/v1/aces",
        200,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "dan")
        )
    );
  }

  @Test
  public void POST_whenTheUserDoesNotHavePermissionToWriteACEs_returnsNotFound() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"" + credentialName + "\","
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

    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    this.mockMvc.perform(post)
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.error").value(expectedError));

    auditingHelper.verifyAuditing(
        "uaa-client:credhub_test",
        "/api/v1/aces",
        404,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, DELETE, "isobel")
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
            + "  \"credential_name\": \"" + credentialName + "\",\n"
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
    PermissionsView acl = JsonHelper.deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), hasSize(2));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("dan", singletonList(READ)))
    ));

    auditingHelper.verifyAuditing(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
        "/api/v1/aces",
        200,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan")
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

    auditingHelper.verifyRequestAuditing(
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
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    this.mockMvc.perform(post).andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error", equalTo(expectedError)));

    auditingHelper.verifyAuditing(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
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
            + "  \"credential_name\": \"" + credentialName + "\",\n"
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

    auditingHelper.verifyRequestAuditing(
        "/api/v1/aces",
        400
    );
  }

  private void verifyAudit(AuditingOperationCode operation, String credentialName, int statusCode) {
    auditingHelper.verifyAuditing(operation, credentialName, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/permissions", statusCode);
  }

  private void seedCredential() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/aces")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"credential_name\": \"" + credentialName + "\",\n"
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
