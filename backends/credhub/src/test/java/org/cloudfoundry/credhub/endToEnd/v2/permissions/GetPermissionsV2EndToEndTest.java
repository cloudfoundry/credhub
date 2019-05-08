package org.cloudfoundry.credhub.endToEnd.v2.permissions;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.MessageSource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
public class GetPermissionsV2EndToEndTest {

  @Autowired
  private MessageSource messageSource;

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
  public void GET_whenUserGivesAPermissionGuid_theyReceiveThePermissions() throws Exception {
    final String credentialName = "/test";
    final UUID credentialUuid = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    final MockHttpServletRequestBuilder getUuidRequest = get("/api/v2/permissions/" + credentialUuid)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String content = mockMvc.perform(getUuidRequest).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), contains(PermissionOperation.WRITE));
    assertThat(returnValue.getUuid(), equalTo(credentialUuid));
  }

  @Test
  public void GET_whenUserGivesAPathAndActor_whenTheyHaveREADACLPermission_theyReceiveThePermission() throws Exception {
    final String credentialName = "/test";
    final UUID credentialUuid = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    final MockHttpServletRequestBuilder getUuidRequest = get("/api/v2/permissions")
      .param("path", credentialName)
      .param("actor", USER_A_ACTOR_ID)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String content = mockMvc.perform(getUuidRequest).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), contains(PermissionOperation.WRITE));
    assertThat(returnValue.getUuid(), equalTo(credentialUuid));
  }

  @Test
  public void GET_whenUserGivesAPermissionGuid_whenTheyDontHaveREADACLPermission_theyReceiveA404() throws Exception {
    final String credentialName = "/test";
    final UUID credentialUuid = PermissionsV2EndToEndTestHelper.setPermissions(mockMvc, credentialName, PermissionOperation.WRITE);

    final MockHttpServletRequestBuilder getUuidRequest = get("/api/v2/permissions/" + credentialUuid)
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(getUuidRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
  }

  @Test
  public void GET_whenUserGivesAPathAndActor_whenTheyDontHaveREADACLPermission_theyReceiveA404() throws Exception {
    final String credentialName = "/test";
    final String actor = "/actor";

    final MockHttpServletRequestBuilder getUuidRequest = get("/api/v2/permissions")
      .param("path", credentialName)
      .param("actor", actor)
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String content = mockMvc.perform(getUuidRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(content).getString("error");
    assertThat(errorMessage, is(equalTo(ErrorMessages.Permissions.INVALID_ACCESS)));
  }

  @Test
  public void GET_whenUserGivesAPathAndActor_whenNoPermissionExists_theyReceiveA404() throws Exception {
    final String credentialName = "/some-nonexistent-credential";
    final String actor = "/actor";

    final MockHttpServletRequestBuilder getUuidRequest = get("/api/v2/permissions")
      .param("path", credentialName)
      .param("actor", actor)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String content = mockMvc.perform(getUuidRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(content).getString("error");
    assertThat(errorMessage, is(equalTo(ErrorMessages.Permissions.INVALID_ACCESS)));
  }

  @Test
  public void GET_whenUserGivesAPathAndActor_whenActorDoesNotExist_theyReceiveA404() throws Exception {
    final String credentialName = "/test";
    final String actor = "/some-nonexistent-actor";

    final MockHttpServletRequestBuilder getUuidRequest = get("/api/v2/permissions")
      .param("path", credentialName)
      .param("actor", actor)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String content = mockMvc.perform(getUuidRequest).andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
    final String errorMessage = new JSONObject(content).getString("error");
    assertThat(errorMessage, is(equalTo(ErrorMessages.Permissions.INVALID_ACCESS)));
  }
}
