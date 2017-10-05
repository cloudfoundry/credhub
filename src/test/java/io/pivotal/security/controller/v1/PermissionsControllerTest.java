package io.pivotal.security.controller.v1;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.handler.PermissionsHandler;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.helper.JsonTestHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.PermissionsView;
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
import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
  private PermissionsDataService permissionsDataService;

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
        "test_credential_name", newArrayList());

    when(permissionsHandler.getPermissions(eq("test_credential_name"), any(UserContext.class)))
        .thenReturn(permissionsView);

    mockMvc.perform(
        get("/api/v1/permissions?credential_name=test_credential_name")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.credential_name").value("test_credential_name"))
        .andExpect(jsonPath("$.permissions").exists());
  }

  @Test
  public void POST_returnsAResponseContainingTheNewPermissions() throws Exception {
    // language=JSON
    String accessControlEntriesJson = "{\n" +
        "  \"credential_name\": \"test-credential-name\",\n" +
        "  \"permissions\": [\n" +
        "    {\n" +
        "      \"actor\": \"test-actor\",\n" +
        "      \"operations\": [\n" +
        "        \"read\",\n" +
        "        \"write\"\n" +/**/
        "      ]\n" +
        "    }\n" +
        "  ]\n" +
        "}";
    // language=JSON
    String expectedResponse = "{\n" +
        "  \"credential_name\": \"test-actor\",\n" +
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

    when(permissionsHandler
        .setPermissions(any(String.class), any(UserContext.class), any(List.class)))
        .thenReturn(JsonTestHelper.deserialize(expectedResponse, PermissionsView.class));

    MockHttpServletRequestBuilder request = post("/api/v1/permissions")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(accessControlEntriesJson);

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().json(expectedResponse));

    ArgumentCaptor<List> captor = ArgumentCaptor.forClass(List.class);
    verify(permissionsHandler, times(1)).setPermissions(
        eq("test-credential-name"),
        any(UserContext.class),
        captor.capture()
    );

    List<PermissionEntry> accessControlEntries = captor.getValue();
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
    when(permissionsDataService.getAllowedOperations("test-name", "test-actor"))
        .thenReturn(Collections.singletonList(PermissionOperation.WRITE));

    mockMvc.perform(
        delete("/api/v1/permissions?credential_name=test-name&actor=test-actor")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isNoContent())
        .andExpect(content().string(""));

    verify(permissionsHandler, times(1))
        .deletePermissionEntry(any(UserContext.class), eq("test-name"), eq("test-actor"));

    auditingHelper.verifyAuditing(
        ACL_DELETE,
        "/test-name",
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        204);
  }

  @Test
  public void DELETE_whenTheCredentialDoesNotExist_logsAnEvent() throws Exception {
    when(permissionsDataService.getAllowedOperations("incorrect-name", "test-actor"))
        .thenReturn(Collections.emptyList());

    Mockito.doThrow(new EntryNotFoundException("error.credential.invalid_access"))
        .when(permissionsHandler)
        .deletePermissionEntry(any(), eq("incorrect-name"), eq("test-actor")
        );

    mockMvc.perform(
        delete("/api/v1/permissions?credential_name=incorrect-name&actor=test-actor")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
    )
        .andExpect(status().isNotFound());

    verify(permissionsHandler, times(1))
        .deletePermissionEntry(any(UserContext.class), eq("incorrect-name"), eq("test-actor")
        );

    EventAuditRecordParameters expectedEntry = new EventAuditRecordParameters(ACL_DELETE, "/incorrect-name", null, "test-actor");

    auditingHelper.verifyAuditing(
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/permissions",
        404,
        Collections.singletonList(expectedEntry)
        );
  }
}
