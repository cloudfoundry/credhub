package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.helper.RequestHelper;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
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

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.credhub.util.AuthConstants.*;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=false")
public class PermissionsEndpointWithoutEnforcementTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private String credentialNameWithoutLeadingSlash = this.getClass().getSimpleName();
  private String credentialName = "/" + credentialNameWithoutLeadingSlash;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    RequestHelper.setPassword(mockMvc, credentialName, "testpassword", ALL_PERMISSIONS_TOKEN);
  }

  @Test
  public void GET_whenTheCredentialNameParameterIsMissing_returnsAnAppropriateError() throws Exception {
    String expectedErrorMessage = "The query parameter credential_name is required for this request.";
    RequestHelper.expectErrorWhenGettingPermissions(
        mockMvc,
        400,
        expectedErrorMessage,
        null,
        NO_PERMISSIONS_TOKEN
    );
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_returnPermissions() throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read"
    );

    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, NO_PERMISSIONS_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(PermissionOperation.READ)))
    ));
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_andTheLeadingSlashIsMissing_returnsPermissions()
      throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read"
    );

    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, NO_PERMISSIONS_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(PermissionOperation.READ)))
    ));
  }

  @Test
  public void GET_whenTheUserLacksPermissionToReadPermissions_stillDisplaysThePermission() throws Exception {
    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, USER_A_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
  }

  @Test
  public void GET_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    String expectedErrorMessage = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    RequestHelper.expectErrorWhenGettingPermissions(
        mockMvc,
        404,
        expectedErrorMessage,
        "/unicorn",
        NO_PERMISSIONS_TOKEN
    );
  }

  @Test
  public void DELETE_whenTheCredentialParameterNameIsMissing_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    RequestHelper.expectErrorWhenDeletingPermissions(
        mockMvc,
        400,
        expectedErrorMessage,
        null,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID
    );
  }

  @Test
  public void DELETE_whenTheActorParameterIsMissing_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The query parameter actor is required for this request.";

    RequestHelper.expectErrorWhenDeletingPermissions(
        mockMvc,
        400,
        expectedErrorMessage,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        null
    );
  }

  @Test
  public void DELETE_whenTheActorIsAllowedToDeletePermissions_shouldDeleteThePermissionEntry() throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        "test-actor",
        "read"
    );

    RequestHelper.revokePermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        "test-actor"
    );
  }

  @Test
  public void DELETE_whenTheActorDoesNotHavePermissionToDeletePermissions_stillDeletesThePermissions()
      throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read"
    );

    RequestHelper.revokePermissions(
        mockMvc,
        credentialName,
        USER_A_TOKEN,
        USER_A_ACTOR_ID
    );
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_shouldReturnNotFound() throws Exception {
    String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    RequestHelper.expectErrorWhenDeletingPermissions(
        mockMvc,
        404,
        expectedError,
        "/not-valid",
        NO_PERMISSIONS_TOKEN,
        "something"
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_returnsPermissions() throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read", "write"
    );

    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_B_ACTOR_ID,
        "delete"
    );

    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, NO_PERMISSIONS_TOKEN);
    assertThat(permissions.getPermissions(), hasSize(2));
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(PermissionOperation.READ, PermissionOperation.WRITE))),
        samePropertyValuesAs(
            new PermissionEntry(USER_B_ACTOR_ID, credentialName, asList(PermissionOperation.DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_updatesPermissions() throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read", "delete"
    );

    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read", "write"
    );

    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, NO_PERMISSIONS_TOKEN);
    assertThat(permissions.getPermissions(), hasSize(1));
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), contains(
        samePropertyValuesAs(
            new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(
                PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserDoesNotHavePermissionToWritePermissions_stillAllowsThemToWritePermissions()
      throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        USER_A_TOKEN,
        USER_A_ACTOR_ID,
        "read", "write"
    );
  }

  @Test
  public void POST_whenTheLeadingSlashIsMissing_prependsTheSlashCorrectly() throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        credentialName,
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read"
    );

    PermissionsView permissions = RequestHelper
        .getPermissions(mockMvc, credentialName, NO_PERMISSIONS_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), hasSize(1));
    assertThat(permissions.getPermissions(), contains(
        samePropertyValuesAs(
            new PermissionEntry(USER_A_ACTOR_ID, credentialName, singletonList(PermissionOperation.READ)))
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
        .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(malformedJson);

    this.mockMvc.perform(post).andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error", equalTo(
            "The request could not be fulfilled because the request path or body did"
                + " not meet expectation. Please check the documentation for required "
                + "formatting and retry your request.")));
  }

  @Test
  public void POST_whenTheCredentialDoesntExist_succeeds() throws Exception {
    RequestHelper.grantPermissions(
        mockMvc,
        "/this-is-a-fake-credential",
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "read"
    );
  }

  @Test
  public void POST_withAnInvalidOperation_returnsBadRequest() throws Exception {
    String expectedErrorMessage = "The provided operation is not supported. Valid values include read, write, delete, read_acl, and write_acl.";
    RequestHelper.expectErrorWhenAddingPermissions(
        mockMvc,
        422,
        expectedErrorMessage,
        "/this-is-a-fake-credential",
        NO_PERMISSIONS_TOKEN,
        USER_A_ACTOR_ID,
        "unicorn"
    );
  }
}
