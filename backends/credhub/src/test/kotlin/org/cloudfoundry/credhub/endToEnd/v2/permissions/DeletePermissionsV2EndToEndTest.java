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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
public class DeletePermissionsV2EndToEndTest {

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
  public void DELETE_whenPermissionIsDeletedForUserA_UserACannotAccessCredentialInAnyWay() throws Exception {
    final String credentialName = "/test";
    final String passwordValue = "passwordValue";

    final UUID credUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isOk());

    final MockHttpServletRequestBuilder deletePermissionRequest = delete("/api/v2/permissions/" + credUUID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String content = mockMvc.perform(deletePermissionRequest).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getUuid(), equalTo(credUUID));
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(PermissionOperation.WRITE)));

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isForbidden());
  }

  @Test
  public void DELETE_whenUserDoesNotHavePermission_CannotDeleteThePermission() throws Exception {
    final String credentialName = "/test";
    final String passwordValue = "passwordValue";

    final UUID credUUID = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isOk());

    final MockHttpServletRequestBuilder deletePermissionRequest = delete("/api/v2/permissions/" + credUUID)
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(deletePermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    PermissionsV2EndToEndTestHelper.setPassword(mockMvc, credentialName, passwordValue, USER_A_TOKEN).andExpect(status().isOk());
  }

  @Test
  public void DELETE_whenUserDeletesAPermission_withAnInvalidGuid_theyReceiveA404() throws Exception {
    final String invalidGuid = "invalid";

    final MockHttpServletRequestBuilder patchPermissionRequest = delete("/api/v2/permissions/" + invalidGuid)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String responseJson = mockMvc.perform(patchPermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The request includes a permission that does not exist.")));
  }

  @Test
  public void DELETE_whenUserDeletesAPermission_withAGuidThatDoeNotExist_theyReceiveA404() throws Exception {
    final String nonExistingGuid = UUID.randomUUID().toString();

    final MockHttpServletRequestBuilder patchPermissionRequest = delete("/api/v2/permissions/" + nonExistingGuid)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String responseJson = mockMvc.perform(patchPermissionRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(responseJson).getString("error");

    assertThat(errorMessage, is(IsEqual.equalTo("The request includes a permission that does not exist.")));
  }

}
