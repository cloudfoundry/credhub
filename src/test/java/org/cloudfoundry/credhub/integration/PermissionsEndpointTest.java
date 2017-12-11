package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.helper.RequestHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsView;
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
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_DELETE;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_UPDATE;
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

    RequestHelper.setPassword(mockMvc, credentialName, "testpassword", CredentialWriteMode.NO_OVERWRITE.mode);

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void GET_whenTheCredentialNameParameterIsMissing_returnsAnAppropriateError()
      throws Exception {
    String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    RequestHelper.expectErrorWhenGettingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        null,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    );
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_returnPermissions() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    PermissionsView permissions = RequestHelper.getPermissions(mockMvc, credentialName,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(PermissionOperation.READ)))
    ));

    verifyAudit(ACL_ACCESS, credentialName, 200);
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_andTheLeadingSlashIsMissing_returnsPermissions()
      throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    PermissionsView permissions = RequestHelper.getPermissions(mockMvc, credentialNameWithoutLeadingSlash,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(PermissionOperation.READ)))
    ));

    verifyAudit(ACL_ACCESS, credentialName, 200);
  }

  @Test
  public void GET_whenTheUserLacksPermissionToReadPermissions_returnsNotFound() throws Exception {
    // Credential was created with UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    RequestHelper.expectErrorWhenGettingPermissions(
        mockMvc,
        404, expectedError,
        credentialName,
        AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN
    );
  }

  @Test
  public void GET_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    String expectedErrorMessage = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    RequestHelper.expectErrorWhenGettingPermissions(
        mockMvc,
        404, expectedErrorMessage,
        "/unicorn",
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    verifyAudit(ACL_ACCESS, "/unicorn", 404);
  }

  @Test
  public void DELETE_whenTheActorIsAllowedToDeletePermissions_shouldDeleteThePermissionEntry()
      throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    RequestHelper.revokePermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan");

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        204,
        newArrayList(new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.READ, "dan"))
    );

    mockMvc.perform(
        get("/api/v1/permissions?credential_name=" + credentialName)
            .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.permissions", hasSize(1)));
  }

  @Test
  public void DELETE_whenTheCredentialParameterNameIsMissing_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    RequestHelper.expectErrorWhenDeletingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        null,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan"
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        400
    );
  }

  @Test
  public void DELETE_whenTheActorParameterIsMissing_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The query parameter actor is required for this request.";

    RequestHelper.expectErrorWhenDeletingPermissions(
        mockMvc,
        400, expectedErrorMessage,
        "octopus",
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, null
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        400
    );
  }

  @Test
  public void DELETE_whenTheActorIsDeletingOwnPermissions_returnsBadRequest() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read");

    RequestHelper.expectStatusWhenDeletingPermissions(
        mockMvc,
        400, credentialName,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN
    );

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        400,
        newArrayList(
            new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.WRITE_ACL,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.WRITE,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.READ_ACL,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.READ,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.DELETE,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID)
        )
    );
  }

  @Test
  public void DELETE_whenTheActorDoesNotHavePermissionToDeletePermissions_returnsNotFound()
      throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "read"
    );

    RequestHelper.expectStatusWhenDeletingPermissions(
        mockMvc,
        404,
        credentialName,
        "dan",
        AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN
    );

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
        "/api/v1/permissions",
        404,
        newArrayList(new EventAuditRecordParameters(ACL_DELETE, credentialName, PermissionOperation.READ, "dan"))
    );

    PermissionsView permissions = RequestHelper.getPermissions(mockMvc, credentialName,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getPermissions(), hasSize(2));
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_shouldReturnNotFound() throws Exception {
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    RequestHelper.expectErrorWhenDeletingPermissions(mockMvc, 404, expectedError, "/not-valid",
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "something"
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        404
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_returnsPermissions()
      throws Exception {
    RequestHelper
        .grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read", "write");
    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.WRITE, "dan")
        )
    );
    RequestHelper
        .grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "isobel", "delete");
    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.DELETE, "isobel")
        )
    );

    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getPermissions(), hasSize(3));
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(PermissionOperation.READ, PermissionOperation.WRITE))),
        samePropertyValuesAs(
            new PermissionEntry("isobel", asList(PermissionOperation.DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_updatesPermissions()
      throws Exception {
    Long initialCount = eventAuditRecordRepository.count();
    RequestHelper.grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "read", "delete");
    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.DELETE, "dan")
        )
    );
    RequestHelper
        .grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan", "write", "read");
    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.WRITE, "dan")
        )
    );

    // 2 from initialPost, 2 from updatePost
    assertThat(eventAuditRecordRepository.count(), equalTo(4L + initialCount));

    PermissionsView acl = RequestHelper
        .getPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(acl.getPermissions(), hasSize(2));
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", asList(
                PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserDoesNotHavePermissionToWritePermissions_returnsNotFound()
      throws Exception {
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    RequestHelper.expectErrorWhenAddingPermissions(
        mockMvc,
        404,
        expectedError,
        credentialName,
        AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN, "dan",
        "read", "write"
    );

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
        "/api/v1/permissions",
        404,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.READ, "dan"),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.WRITE, "dan")
        )
    );
  }

  @Test
  public void POST_whenTheUserUpdatesHisOwnPermissions_returnsBadRequest() throws Exception {
    final String expectedError = "Modification of access control for the authenticated user is not allowed. Please contact an administrator.";
    RequestHelper.expectErrorWhenAddingPermissions(
        mockMvc,
        400, expectedError,
        credentialName,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "read", "write"
    );

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        400,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.READ,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.WRITE,
                AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID)
        )
    );
  }

  @Test
  public void POST_whenTheLeadingSlashIsMissing_prependsTheSlashCorrectly() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "read");
    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        201,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, credentialName, PermissionOperation.READ, "dan")
        )
    );

    PermissionsView acl = RequestHelper
        .getPermissions(mockMvc, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), hasSize(2));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("dan", singletonList(PermissionOperation.READ)))
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
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
    RequestHelper.expectErrorWhenAddingPermissions(
        mockMvc,
        404, expectedError,
        "/this-is-a-fake-credential",
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "read"
    );

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        404,
        newArrayList(
            new EventAuditRecordParameters(ACL_UPDATE, "/this-is-a-fake-credential", PermissionOperation.READ, "dan")
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
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "dan",
        "unicorn"
    );

    auditingHelper.verifyRequestAuditing(
        "/api/v1/permissions",
        400
    );
  }

  private void verifyAudit(AuditingOperationCode operation, String credentialName, int statusCode) {
    auditingHelper.verifyAuditing(operation, credentialName, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions", statusCode);
  }
}
