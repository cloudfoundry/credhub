package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.handler.PermissionsHandler;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.helper.RequestHelper.expectStatusWhenDeletingPermissions;
import static org.cloudfoundry.credhub.helper.RequestHelper.getPermissions;
import static org.cloudfoundry.credhub.helper.RequestHelper.grantPermissions;
import static org.cloudfoundry.credhub.helper.RequestHelper.revokePermissions;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class PermissionsControllerTest {
  @MockBean
  private PermissionsHandler permissionsHandler;

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @MockBean
  private PermissionDataService permissionDataService;

  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;

  @Before
  public void beforeEach() {
    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);

    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void GET_returnsThePermissionsForTheCredential() throws Exception {
    PermissionsView permissionsView = new PermissionsView(
        "/test_credential_name", newArrayList());

    when(permissionsHandler.getPermissions(eq("/test_credential_name"), any(List.class)))
        .thenReturn(permissionsView);

    PermissionsView permissions = getPermissions(mockMvc, "/test_credential_name",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo("/test_credential_name"));
    assertThat(permissions.getPermissions(), hasSize(0));
  }

  @Test
  public void GET_whenTheCredentialNameDoesNotHaveALeadingSlash_returnsThePermissionsForTheCredential() throws Exception {
    PermissionsView permissionsView = new PermissionsView(
        "/test_credential_name", newArrayList());

    when(permissionsHandler.getPermissions(eq("/test_credential_name"), any(List.class)))
        .thenReturn(permissionsView);

    PermissionsView permissions = getPermissions(mockMvc, "test_credential_name",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    assertThat(permissions.getCredentialName(), equalTo("/test_credential_name"));
    assertThat(permissions.getPermissions(), hasSize(0));
  }

  @Test
  public void POST_returnsASuccessfulEmptyResponse() throws Exception {
    grantPermissions(mockMvc, "test-credential-name", UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "test-actor",
        "read", "write");

    ArgumentCaptor<PermissionsRequest> captor = ArgumentCaptor.forClass(PermissionsRequest.class);
    verify(permissionsHandler, times(1)).setPermissions(
        captor.capture(),
        any(List.class)
    );

    PermissionsRequest permissionsRequest = captor.getValue();
    List<PermissionEntry> accessControlEntries = permissionsRequest.getPermissions();
    assertThat(accessControlEntries,
        hasItem(allOf(hasProperty("actor", equalTo("test-actor")),
            hasProperty("allowedOperations",
                hasItems(PermissionOperation.READ, PermissionOperation.WRITE)))));
  }

  @Test
  public void POST_validatesRequestJson() throws Exception {
    // language=JSON
    String accessControlEntriesJson = "{\n" +
        // no credential_name
        "  \"permissions\": [\n" +
        "    {\n" +
        "      \"actor\": \"test-actor\",\n" +
        "      \"operations\": [\n" +
        "        \"read\",\n" +
        "        \"write\"\n" +
        "      ]\n" +
        "    }\n" +
        "  ]\n" +
        "}";

    MockHttpServletRequestBuilder request = post("/api/v1/permissions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(accessControlEntriesJson);

    mockMvc.perform(request)
        .andExpect(status().isBadRequest());
  }

  @Test
  public void DELETE_removesThePermissions() throws Exception {
    when(permissionDataService.getAllowedOperations("/test-name", "test-actor"))
        .thenReturn(Collections.singletonList(PermissionOperation.WRITE));

    revokePermissions(mockMvc, "/test-name", UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "test-actor");

    verify(permissionsHandler, times(1))
        .deletePermissionEntry(eq("/test-name"), eq("test-actor"), any(List.class));
  }

  @Test
  public void DELETE_whenTheCredentialNameDoesNotHaveALeadingSlash_removesThePermissions() throws Exception {
    when(permissionDataService.getAllowedOperations("/test-name", "test-actor"))
        .thenReturn(Collections.singletonList(PermissionOperation.WRITE));

    revokePermissions(mockMvc, "test-name", UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "test-actor");

    verify(permissionsHandler, times(1))
        .deletePermissionEntry(eq("/test-name"), eq("test-actor"), any(List.class));
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_logsAnEvent() throws Exception {
    when(permissionDataService.getAllowedOperations("/incorrect-name", "test-actor"))
        .thenReturn(Collections.emptyList());

    Mockito.doThrow(new EntryNotFoundException("error.credential.invalid_access"))
        .when(permissionsHandler)
        .deletePermissionEntry(eq("/incorrect-name"), eq("test-actor"), any(List.class));

    expectStatusWhenDeletingPermissions(mockMvc, 404, "incorrect-name", "test-actor", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    verify(permissionsHandler, times(1))
        .deletePermissionEntry(eq("/incorrect-name"), eq("test-actor"), any(List.class));
  }
}
