package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
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
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;
import java.util.List;

import static java.util.Arrays.asList;
import static org.cloudfoundry.credhub.request.PermissionOperation.*;
import static org.cloudfoundry.credhub.util.AuthConstants.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = {CredentialManagerApp.class})
@Transactional
public class PermissionAndCredentialTest {

  public static final String MTLS_APP_GUID = "mtls-app:app1-guid";
  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void putCredential() throws Exception {
    String requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\",\n" +
        "  \"value\":\"ORIGINAL-VALUE\"\n" +
        "}";

    final ResultActions result = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertCredentialCreated(result);
  }

  @Test
  public void postCredential() throws Exception {
    String requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\"\n" +
        "}";

    final ResultActions result = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertCredentialCreated(result);
  }

    @Test
  public void put_withNewPermission() throws Exception {
    String requestBody = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"value\":\"ORIGINAL-VALUE\",\n"
        + "  \"additional_permissions\": [{\n"
        + "  \"actor\": \"" + USER_B_ACTOR_ID + "\",\n"
        + "  \"operations\": [\"read\"]\n"
        + "  }]\n"
        + "}";

    final ResultActions result = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertCredentialCreated(result);
    hasPermission(USER_B_ACTOR_ID, Collections.singletonList(PermissionOperation.READ));
  }

  @Test
  public void post_withNewPermission() throws Exception {
    String requestBody = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"additional_permissions\": [{\n"
        + "    \"actor\": \"" + USER_B_ACTOR_ID + "\",\n"
        + "    \"operations\": [\"read\"]\n"
        + "  }]\n"
        + "}";

    final ResultActions result = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertCredentialCreated(result);
    hasPermission(USER_B_ACTOR_ID, Collections.singletonList(PermissionOperation.READ));
  }

  @Test
  public void put_withExistingCredentialAndAnAce() throws Exception {
    createExistingCredential();

    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"value\":\"ORIGINAL-VALUE\", \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + USER_B_ACTOR_ID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces));

    assertAclUpdated(response, ALL_PERMISSIONS_TOKEN);
  }

  @Test
  public void post_withExistingCredentialAndAPermission_andOverwriteSetToTrue_itDoesUpdatePermissions() throws Exception {
    createExistingCredential();

    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + USER_B_ACTOR_ID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces))
        .andDo(print());

    assertAclUpdated(response, ALL_PERMISSIONS_TOKEN);
  }

  @Test
  public void post_withExistingCredentialAndAnAce_andOverwriteSetToFalse() throws Exception {
    createExistingCredential();

    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":false, \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + USER_B_ACTOR_ID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces));

    response
        .andExpect(status().isOk())
        .andDo(print())
        .andExpect(jsonPath("$.type", equalTo("password")));

    MvcResult result = mockMvc
        .perform(get("/api/v1/permissions?credential_name=" + "/test-password")
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo("/test-password"));
    assertThat(acl.getPermissions(), contains(
        samePropertyValuesAs(new PermissionEntry(USER_A_ACTOR_ID, "/test-password", asList(READ, WRITE)))));
  }

  @Test
  public void put_whenRequestingInvalidPermissionOperation_returnsAnError() throws Exception {
    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\n"
            + "  \"type\":\"password\",\n"
            + "  \"name\":\"/test-password\",\n"
            + "  \"value\":\"ORIGINAL-VALUE\", \n"
            + "  \"additional_permissions\": [{\n"
            + "    \"actor\": \"" + MTLS_APP_GUID + "\",\n"
            + "    \"operations\": [\"unicorn\"]\n"
            + "  }]\n"
            + "}");

    this.mockMvc.perform(put).andExpect(status().is4xxClientError())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(
            "The provided operation is not supported."
                + " Valid values include read, write, delete, read_acl, and write_acl."));
  }

  @Test
  public void post_whenRequestingInvalidPermissionOperation_returnsAnError() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\n"
            + "  \"type\":\"password\",\n"
            + "  \"name\":\"/test-password\",\n"
            + "  \"additional_permissions\": [{\n"
            + "    \"actor\": \"" + MTLS_APP_GUID + "\",\n"
            + "    \"operations\": [\"unicorn\"]\n"
            + "  }]\n"
            + "}");

    this.mockMvc.perform(post).andExpect(status().isUnprocessableEntity())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(
            "The provided operation is not supported."
                + " Valid values include read, write, delete, read_acl, and write_acl."));
  }

  private void createExistingCredential() throws Exception {
    String requestBody = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"additional_permissions\": [{\n"
        + "    \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "    \"operations\": [\"read\", \"write\"]\n"
        + "  }]"
        + "}";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.type", equalTo("password")));
  }

  private void assertCredentialCreated(ResultActions result)
      throws Exception {
    result
        .andExpect(status().isOk())
        .andDo(print())
        .andExpect(jsonPath("$.type", equalTo("password")));
  }

  private void assertAclUpdated(ResultActions result, String token)
      throws Exception {
    result
        .andExpect(status().isOk())
        .andDo(print())
        .andExpect(jsonPath("$.type", equalTo("password")));

    MvcResult getPermissionResult = mockMvc
        .perform(get("/api/v1/permissions?credential_name=/test-password")
            .header("Authorization", "Bearer " + token))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = getPermissionResult.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo("/test-password"));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(USER_B_ACTOR_ID, "/test-password", asList(WRITE))),
        samePropertyValuesAs(
            new PermissionEntry(USER_A_ACTOR_ID, "/test-password", asList(READ, WRITE, DELETE)))));
  }

  private PermissionsView getAcl(String token) throws Exception {
    MvcResult result = mockMvc
        .perform(get("/api/v1/permissions?credential_name=/test-password")
            .header("Authorization", "Bearer " + token))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo("/test-password"));
    return acl;
  }

  private void hasPermission(String actorId, List<PermissionOperation> operations) throws Exception {
    assertThat(getAcl(ALL_PERMISSIONS_TOKEN).getPermissions(), contains(
        samePropertyValuesAs(
            new PermissionEntry(actorId, "/test-password", operations))));
  }
}
