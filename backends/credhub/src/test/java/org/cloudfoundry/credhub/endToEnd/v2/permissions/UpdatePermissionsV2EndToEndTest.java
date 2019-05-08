package org.cloudfoundry.credhub.endToEnd.v2.permissions;

import java.util.Collections;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.hamcrest.core.IsEqual;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
@Transactional
public class UpdatePermissionsV2EndToEndTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void PATCH_whenUserGivesAPermission_forAPathAndActorThatDoesNotExist_theyReceiveA404() throws Exception {
    final String invalidGuid = "invalid";

    final MockHttpServletRequestBuilder patchPermissionRequest = patch("/api/v2/permissions/" + invalidGuid)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String responseJson = mockMvc.perform(patchPermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The request includes a permission that does not exist.")));
  }

  @Test
  public void PATCH_whenWriteIsEnabledOnExistingPermissionForUserA_UserACanCreateCredentials() throws Exception {
    final String credentialName = "/test";
    final String passwordValue = "passwordValue";

    final UUID permissionUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.READ);

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isForbidden());

    final MockHttpServletRequestBuilder patchPermissionRequest = patch("/api/v2/permissions/" + permissionUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String content = mockMvc.perform(patchPermissionRequest).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getUuid(), equalTo(permissionUUID));
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(PermissionOperation.WRITE)));

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isOk());
  }


  @Test
  public void PATCH_whenUserDoesNotHavePermissionOnPath_theyCannotAddAPermission() throws Exception {
    final String credentialName = "/test";

    final UUID permissionUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.READ);

    final MockHttpServletRequestBuilder patchPermissionRequest = patch("/api/v2/permissions/" + permissionUUID)
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"operations\": [\"write\"]\n"
        + "}");

    mockMvc.perform(patchPermissionRequest).andExpect(status().isNotFound());
  }

  @Test
  public void PUT_whenUserDoesNotHavePermissionOnPath_theyCannotAddAPermission() throws Exception {
    final String credentialName = "/test";

    final UUID permissionUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.READ);

    final MockHttpServletRequestBuilder putPermissionRequest = put("/api/v2/permissions/" + permissionUUID)
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    mockMvc.perform(putPermissionRequest).andExpect(status().isNotFound());
  }


  @Test
  public void PUT_whenWriteIsEnabledOnExistingPermissionForUserA_UserACanCreateCredentials() throws Exception {
    final String credentialName = "/test";
    final String passwordValue = "passwordValue";

    final UUID credUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.READ);

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isForbidden());

    final MockHttpServletRequestBuilder putPermissionRequest = put("/api/v2/permissions/" + credUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String content = mockMvc.perform(putPermissionRequest).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getUuid(), equalTo(credUUID));
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(PermissionOperation.WRITE)));

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isOk());
  }

  @Test
  public void PUT_whenUUIDDoesNotMatchGivenActorAndPath_ReturnStatusBadRequest() throws Exception {
    final String credentialName = "/test";
    final String badCredentialName = "/wrongName";
    final String passwordValue = "passwordValue";

    final UUID credUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.READ);

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isForbidden());

    final MockHttpServletRequestBuilder putPermissionRequest = put("/api/v2/permissions/" + credUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + badCredentialName + "\",\n"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String responseJson = mockMvc.perform(putPermissionRequest).andExpect(status().isBadRequest()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The permission guid does not match the provided actor and path.")));
  }

  @Test
  public void PUT_whenUUIDDoesNotExist_ReturnStatusNotFound() throws Exception {
    final String credUUID = "1550919c-b7e1-4288-85fd-c73220e6ac5f";

    final MockHttpServletRequestBuilder putPermissionRequest = put("/api/v2/permissions/" + credUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + "badCredentialName" + "\",\n"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String responseJson = mockMvc.perform(putPermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The request includes a permission that does not exist.")));
  }

  @Test
  public void PUT_whenUUIDIsInvalid_ReturnStatusNotFound() throws Exception {
    final String credUUID = "not-a-uuid";

    final MockHttpServletRequestBuilder putPermissionRequest = put("/api/v2/permissions/" + credUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + "badCredentialName" + "\",\n"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String responseJson = mockMvc.perform(putPermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The request includes a permission that does not exist.")));
  }

  @Test
  public void PUT_whenUserGivesAPermission_forAPathAndActorThatDoesNotExist_theyReceiveA404() throws Exception {
    final String credentialName = "does_not_exist";
    final String fakeUUID = "fake_guid";

    final MockHttpServletRequestBuilder putPermissionRequest = put("/api/v2/permissions/" + fakeUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"" + "write" + "\"]\n"
        + "}");

    final String responseJson = mockMvc.perform(putPermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The request includes a permission that does not exist.")));
  }

}
