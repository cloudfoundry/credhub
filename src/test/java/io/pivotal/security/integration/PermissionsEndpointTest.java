package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.helper.RequestHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.PermissionsView;
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

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.helper.RequestHelper.expectErrorWhenAddingPermissions;
import static io.pivotal.security.helper.RequestHelper.expectErrorWhenDeletingPermissions;
import static io.pivotal.security.helper.RequestHelper.expectErrorWhenGettingPermissions;
import static io.pivotal.security.helper.RequestHelper.expectStatusWhenDeletingPermissions;
import static io.pivotal.security.helper.RequestHelper.getPermissions;
import static io.pivotal.security.helper.RequestHelper.grantPermissions;
import static io.pivotal.security.helper.RequestHelper.revokePermissions;
import static io.pivotal.security.helper.RequestHelper.setPassword;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
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

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;
  private String credentialNameWithoutLeadingSlash = this.getClass().getSimpleName();
  private String credentialName = "/" + credentialNameWithoutLeadingSlash;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    setPassword(mockMvc, credentialName, "testpassword");

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void GET_whenTheCredentialNameParameterIsMissing_returnsAnAppropriateError()
      throws Exception {
    String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    expectErrorWhenGettingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        null,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    );
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_returnPermissions() throws Exception {
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    PermissionsView permissions = getPermissions(mockMvc, credentialName,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(READ)))
    ));

    verifyAudit(ACL_ACCESS, credentialName, 200);
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_andTheLeadingSlashIsMissing_returnsPermissions()
      throws Exception {
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    PermissionsView permissions = getPermissions(mockMvc, credentialNameWithoutLeadingSlash,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(READ)))
    ));

    verifyAudit(ACL_ACCESS, credentialName, 200);
  }

  @Test
  public void GET_whenTheUserLacksPermissionToReadPermissions_returnsNotFound() throws Exception {
    // Credential was created with UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    expectErrorWhenGettingPermissions(
        mockMvc,
        404, expectedError,
        credentialName,
        UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN
    );
  }

  @Test
  public void GET_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    String expectedErrorMessage = "The request could not be fulfilled because the resource could not be found.";

    expectErrorWhenGettingPermissions(
        mockMvc,
        404, expectedErrorMessage,
        "/unicorn",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    verifyAudit(ACL_ACCESS, "/unicorn", 404);
  }

  @Test
  public void DELETE_whenTheActorIsAllowedToDeletePermissions_shouldDeleteThePermissionEntry()
      throws Exception {
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    revokePermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan");

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
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
  public void DELETE_whenTheCredentialParameterNameIsMissing_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    expectErrorWhenDeletingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        null,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan"
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        400
    );
  }

  @Test
  public void DELETE_whenTheActorParameterIsMissing_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The query parameter actor is required for this request.";

    expectErrorWhenDeletingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        "octopus",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, null
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        400
    );
  }

  @Test
  public void DELETE_whenTheActorIsDeletingOwnPermissions_returnsBadRequest() throws Exception {
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    expectStatusWhenDeletingPermissions(
        mockMvc,
        400, credentialName,
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    );

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        400,
        newArrayList(
            new EventAuditRecordParameters(ACL_DELETE, credentialName, WRITE_ACL,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, WRITE,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, READ_ACL,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, READ,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, DELETE,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID)
        )
    );
  }

  @Test
  public void DELETE_whenTheActorDoesNotHavePermissionToDeletePermissions_returnsNotFound()
      throws Exception {
    grantPermissions(
        mockMvc,
        credentialName,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "read"
    );

    expectStatusWhenDeletingPermissions(
        mockMvc,
        404,
        credentialName,
        "dan",
        UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN
    );

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
        "/api/v1/permissions",
        404,
        newArrayList(new EventAuditRecordParameters(ACL_DELETE, credentialName, READ, "dan"))
    );

    PermissionsView permissions = getPermissions(mockMvc, credentialName,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getPermissions(), hasSize(2));
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_shouldReturnNotFound() throws Exception {
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    expectErrorWhenDeletingPermissions(mockMvc, 404, expectedError, "/not-valid",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "something"
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        404
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_returnsPermissions()
      throws Exception {
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read", "write");
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "dan")
        )
    );
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "isobel", "delete");
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, DELETE, "isobel")
        )
    );

    PermissionsView acl = getPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(acl.getPermissions(), hasSize(3));
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(READ, WRITE))),
        samePropertyValuesAs(
            new PermissionEntry("isobel", asList(DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_updatesPermissions()
      throws Exception {
    Long initialCount = eventAuditRecordRepository.count();
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read", "delete");
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, DELETE, "dan")
        )
    );
    grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "write", "read");
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "dan")
        )
    );

    // 2 from initialPost, 2 from updatePost
    assertThat(eventAuditRecordRepository.count(), equalTo(4L + initialCount));

    PermissionsView acl = getPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(acl.getPermissions(), hasSize(2));
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(READ, WRITE, DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserDoesNotHavePermissionToWritePermissions_returnsNotFound()
      throws Exception {
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    expectErrorWhenAddingPermissions(
        mockMvc,
        404,
        expectedError,
        credentialName,
        UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN, "dan",
        "read", "write"
    );

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
        "/api/v1/permissions",
        404,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "dan")
        )
    );
  }

  @Test
  public void POST_whenTheUserUpdatesHisOwnPermissions_returnsBadRequest() throws Exception {
    final String expectedError = "Modification of access control for the authenticated user is not allowed. Please contact an administrator.";
    expectErrorWhenAddingPermissions(
        mockMvc,
        400, expectedError,
        credentialName,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "read", "write"
    );

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        400,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE,
                UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID)
        )
    );
  }

  @Test
  public void POST_whenTheLeadingSlashIsMissing_prependsTheSlashCorrectly() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "read");
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "dan")
        )
    );

    PermissionsView acl = getPermissions(mockMvc, credentialName, UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), hasSize(2));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", singletonList(READ)))
    ));
  }

  @Test
  public void POST_whenMalformedJsonIsSent_returnsBadRequest() throws Exception {
    final String malformedJson = "{"
        + "  \"credential_name\": \"foo\","
        + "  \"permissions\": ["
        + "     {"
        + "       \"actor\": \"dan\","
        + "       \"operations\":"
        + "     }]"
        + "}";
    final MockHttpServletRequestBuilder post = post("/api/v1/permissions")
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
        "/api/v1/permissions",
        400
    );
  }

  @Test
  public void POST_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    expectErrorWhenAddingPermissions(
        mockMvc,
        404, expectedError,
        "/this-is-a-fake-credential",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "read"
    );

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        404,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, "/this-is-a-fake-credential", READ, "dan")
        )
    );
  }

  @Test
  public void POST_withAnInvalidOperation_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The provided operation is not supported."
        + " Valid values include read, write, delete, read_acl, and write_acl.";

    RequestHelper.expectErrorWhenAddingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        credentialName,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "unicorn"
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        400
    );
  }

  private void verifyAudit(AuditingOperationCode operation, String credentialName, int statusCode) {
    auditingHelper.verifyAuditing(operation, credentialName, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions", statusCode);
  }
}
