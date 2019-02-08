package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.helpers.RequestHelper;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.views.PermissionsView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_B_ACTOR_ID;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
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
@SpringBootTest(classes = CredhubTestApp.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@Transactional
public class PermissionsEndpointTest {
  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private final String credentialNameWithoutLeadingSlash = this.getClass().getSimpleName();
  private final String credentialName = "/" + credentialNameWithoutLeadingSlash;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    RequestHelper.setPassword(mockMvc, credentialName, "testpassword", ALL_PERMISSIONS_TOKEN);
  }

  @Test
  public void GET_whenTheCredentialNameParameterIsMissing_returnsAnAppropriateError()
    throws Exception {
    final String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    RequestHelper.expectErrorWhenGettingPermissions(
      mockMvc,
      400, expectedErrorMessage,
      null,
      ALL_PERMISSIONS_TOKEN
    );
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_returnPermissions() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read");

    final PermissionsView permissions = RequestHelper.getPermissions(mockMvc, credentialName,
      ALL_PERMISSIONS_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), contains(
      samePropertyValuesAs(
        new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(PermissionOperation.READ)))
    ));
  }

  @Test
  public void GET_whenTheUserHasPermissionToAccessPermissions_andTheLeadingSlashIsMissing_returnsPermissions()
    throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read");

    final PermissionsView permissions = RequestHelper.getPermissions(mockMvc, credentialNameWithoutLeadingSlash, ALL_PERMISSIONS_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo(credentialName));
    assertThat(permissions.getPermissions(), contains(
      samePropertyValuesAs(new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(PermissionOperation.READ)))
    ));
  }

  @Test
  public void GET_whenTheUserLacksPermissionToReadPermissions_returnsNotFound() throws Exception {
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    RequestHelper.expectErrorWhenGettingPermissions(
      mockMvc,
      404, expectedError,
      credentialName,
      USER_A_TOKEN
    );
  }

  @Test
  public void GET_whenTheCredentialDoesntExist_returnsNotFound() throws Exception {
    final String expectedErrorMessage = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    RequestHelper.expectErrorWhenGettingPermissions(
      mockMvc,
      404, expectedErrorMessage,
      "/unicorn",
      ALL_PERMISSIONS_TOKEN);
  }

  @Test
  public void DELETE_whenTheActorIsAllowedToDeletePermissions_shouldDeleteThePermissionEntry()
    throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read");
    RequestHelper.revokePermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID);

    mockMvc.perform(
      get("/api/v1/permissions?credential_name=" + credentialName)
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
    )
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.permissions", is(empty())));
  }

  @Test
  public void DELETE_whenTheCredentialParameterNameIsMissing_returnsBadRequest() throws Exception {
    final String expectedErrorMessage = "The query parameter credential_name is required for this request.";

    RequestHelper.expectErrorWhenDeletingPermissions(
      mockMvc,
      400, expectedErrorMessage,
      null,
      ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID
    );
  }

  @Test
  public void DELETE_whenTheActorParameterIsMissing_returnsBadRequest() throws Exception {
    final String expectedErrorMessage = "The query parameter actor is required for this request.";

    RequestHelper.expectErrorWhenDeletingPermissions(
      mockMvc,
      400, expectedErrorMessage,
      "octopus",
      ALL_PERMISSIONS_TOKEN, null
    );
  }

  @Test
  public void DELETE_whenTheActorIsDeletingOwnPermissions_returnsBadRequest() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read");

    RequestHelper.expectStatusWhenDeletingPermissions(
      mockMvc,
      400, credentialName,
      ALL_PERMISSIONS_ACTOR_ID,
      ALL_PERMISSIONS_TOKEN
    );
  }

  @Test
  public void DELETE_whenTheActorDoesNotHavePermissionToDeletePermissions_returnsNotFound() throws Exception {
    RequestHelper.grantPermissions(
      mockMvc,
      credentialName,
      ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID,
      "read"
    );

    RequestHelper.expectStatusWhenDeletingPermissions(
      mockMvc,
      404,
      credentialName,
      USER_A_ACTOR_ID,
      USER_A_TOKEN
    );

    final PermissionsView permissions = RequestHelper.getPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN);
    assertThat(permissions.getPermissions(), hasSize(1));
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_shouldReturnNotFound() throws Exception {
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    RequestHelper.expectErrorWhenDeletingPermissions(mockMvc, 404, expectedError, "/not-valid",
      ALL_PERMISSIONS_TOKEN, "something"
    );
  }

  @Test
  public void POST_whenTheUserHasPermissionToWritePermissions_returnsPermissions() throws Exception {
    RequestHelper
      .grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read", "write");
    RequestHelper
      .grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_B_ACTOR_ID, "delete");

    final PermissionsView permissions = RequestHelper
      .getPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN);
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
    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read", "delete");

    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "write", "read");

    final PermissionsView acl = RequestHelper
      .getPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN);
    assertThat(acl.getPermissions(), hasSize(1));
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), contains(
      samePropertyValuesAs(
        new PermissionEntry(USER_A_ACTOR_ID, credentialName, asList(
          PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE)))
    ));
  }

  @Test
  public void POST_whenTheUserDoesNotHavePermissionToWritePermissions_returnsNotFound() throws Exception {
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    RequestHelper.expectErrorWhenAddingPermissions(
      mockMvc,
      404,
      expectedError,
      credentialName,
      USER_A_TOKEN, USER_A_ACTOR_ID,
      "read", "write"
    );
  }

  @Test
  public void POST_whenTheUserUpdatesHisOwnPermissions_returnsBadRequest() throws Exception {
    final String expectedError = "Modification of access control for the authenticated user is not allowed. Please contact an administrator.";
    RequestHelper.expectErrorWhenAddingPermissions(
      mockMvc,
      400, expectedError,
      credentialName,
      ALL_PERMISSIONS_TOKEN, ALL_PERMISSIONS_ACTOR_ID,
      "read", "write"
    );
  }

  @Test
  public void POST_whenTheLeadingSlashIsMissing_prependsTheSlashCorrectly() throws Exception {
    RequestHelper.grantPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID,
      "read");

    final PermissionsView acl = RequestHelper
      .getPermissions(mockMvc, credentialName, ALL_PERMISSIONS_TOKEN);
    assertThat(acl.getCredentialName(), equalTo(credentialName));
    assertThat(acl.getPermissions(), hasSize(1));
    assertThat(acl.getPermissions(), contains(
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
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
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
    RequestHelper
      .grantPermissions(mockMvc, "/this-is-a-fake-credential", ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID,
        "read", "write");
  }

  @Test
  public void POST_withAnInvalidOperation_returnsBadRequest() throws Exception {
    final String expectedErrorMessage = "The provided operation is not supported."
      + " Valid values include read, write, delete, read_acl, and write_acl.";

    RequestHelper.expectErrorWhenAddingPermissions(
      mockMvc,
      422, expectedErrorMessage,
      credentialName,
      ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID,
      "unicorn"
    );
  }
}
