package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.Collections;

import static org.cloudfoundry.credhub.util.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = {"unit-test", "unit-test-permissions"}, resolver = DatabaseProfileResolver.class)
@Transactional
public class PermissionsEndpointV2Test {

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
    String credentialName = "/test";

    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
            + "  \"path\": \"" + credentialName + "\",\n"
            + "  \"operations\": [\"write\"]\n"
            + "}");

    String content = mockMvc.perform(addPermissionRequest).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(PermissionOperation.WRITE)));


    MockHttpServletRequestBuilder writeCredentialRequest = put("/api/v1/data")
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
    String credentialName = "/test";

    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
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
    String credentialName = "/test";

    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
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
    String credentialName = "/user-a/*";

    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
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
  public void POST_whenUserTriesToAddAnAdditionalOperationToAPermissionThatAlreadyExists_theySucceed() throws Exception {
    String credentialName = "/test";

    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
            + "  \"path\": \"" + credentialName + "\",\n"
            + "  \"operations\": [\"write\"]\n"
            + "}");

    String content = mockMvc.perform(addPermissionRequest).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(PermissionOperation.WRITE)));

    MockHttpServletRequestBuilder addPermissionRequestWithRead = post("/api/v2/permissions")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
            + "  \"path\": \"" + credentialName + "\",\n"
            + "  \"operations\": [\"write\", \"read\"]\n"
            + "}");

    content = mockMvc.perform(addPermissionRequestWithRead).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Arrays.asList(PermissionOperation.WRITE, PermissionOperation.READ)));






  }
}
