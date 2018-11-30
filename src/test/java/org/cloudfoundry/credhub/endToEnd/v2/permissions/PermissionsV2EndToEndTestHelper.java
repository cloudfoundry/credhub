package org.cloudfoundry.credhub.endToEnd.v2.permissions;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.view.PermissionsV2View;

import static org.cloudfoundry.credhub.util.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_ACTOR_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

final class PermissionsV2EndToEndTestHelper {

  private PermissionsV2EndToEndTestHelper() {
  }

  static UUID setPermissions(MockMvc mockMvc, String credentialName, PermissionOperation operation) throws Exception {
    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"" + operation.getOperation() + "\"]\n"
        + "}");

    String content = mockMvc.perform(addPermissionRequest).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(operation)));

    assertThat(returnValue.getUuid(), notNullValue());

    return returnValue.getUuid();
  }

  static ResultActions setPassword(MockMvc mockMvc, String credentialName, String passwordValue, String token) throws Exception {
    Map<String, String> passwordRequestBody = new HashMap<>();

    passwordRequestBody.put("name", credentialName);
    passwordRequestBody.put("type", "password");
    passwordRequestBody.put("value", passwordValue);

    String content = JsonTestHelper.serializeToString(passwordRequestBody);

    MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    return mockMvc.perform(put);
  }
}
