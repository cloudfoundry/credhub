package org.cloudfoundry.credhub.endToEnd.v2.permissions;

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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
public class AddPermissionsV2EndToEndTest {

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
  public void POST_whenUserHasPermissionOnPath_theyCanAddAPermission() throws Exception {
    final String credentialName = "/test";

    PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    final MockHttpServletRequestBuilder writeCredentialRequest = put("/api/v1/data")
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"name\": \"" + credentialName + "\",\n"
        + "  \"value\": \"test-value\",\n"
        + "  \"type\": \"password\"\n"
        + "}");

    mockMvc.perform(writeCredentialRequest).andExpect(status().isOk());
  }

  @Test
  public void POST_whenUserDoesNotHavePermissionOnPath_theyCannotAddAPermission() throws Exception {
    final String credentialName = "/test";

    final MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"write\"]\n"
        + "}");

    mockMvc.perform(addPermissionRequest).andExpect(status().isNotFound());
  }

  @Test
  public void POST_whenUserTriesToAddOperationThatDoesntExist_theyReceiveAnUnprocessibleEntry() throws Exception {
    final String credentialName = "/test";

    final MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"bad_operation\"]\n"
        + "}");

    mockMvc.perform(addPermissionRequest).andExpect(status().isUnprocessableEntity());
  }

  @Test
  public void POST_whenUserTriesToAddAPermissionThatAlreadyExists_theyReceiveAConflict() throws Exception {
    final String credentialName = "/user-a/*";

    final MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"read\"]\n"
        + "}");

    mockMvc.perform(addPermissionRequest).andExpect(status().isConflict());
  }

  @Test
  public void POST_whenUserTriesToAddAnAdditionalOperationToAPermissionThatAlreadyExists_theyReceiveAConflict() throws Exception {
    final String credentialName = "/test";

    PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    final MockHttpServletRequestBuilder addPermissionRequestWithRead = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"write\", \"read\"]\n"
        + "}");

    mockMvc.perform(addPermissionRequestWithRead).andExpect(status().isConflict());
  }

  @Test
  public void POST_whenUserTriesToGrantPermissionsToSelf_theyCannotAddAPermission() throws Exception {
    final String credentialName = "/test";

    PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    final MockHttpServletRequestBuilder addPermissionRequestWithRead = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + ALL_PERMISSIONS_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"write\", \"read\"]\n"
        + "}");

    mockMvc.perform(addPermissionRequestWithRead).andExpect(status().isBadRequest());
  }

}
