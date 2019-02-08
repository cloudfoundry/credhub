package org.cloudfoundry.credhub.endToEnd.v2.permissions;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.views.PermissionsV2View;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

final class PermissionsV2EndToEndTestHelper {

  private PermissionsV2EndToEndTestHelper() {
    super();
  }

  static UUID setPermissions(final MockMvc mockMvc, final String credentialName, final PermissionOperation operation) throws Exception {
    final MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "  \"path\": \"" + credentialName + "\",\n"
        + "  \"operations\": [\"" + operation.getOperation() + "\"]\n"
        + "}");

    final String content = mockMvc.perform(addPermissionRequest).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(credentialName));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(operation)));

    assertThat(returnValue.getUuid(), notNullValue());

    return returnValue.getUuid();
  }

  static ResultActions setPassword(
    final MockMvc mockMvc, final String credentialName, final String passwordValue, final String token) throws Exception {
    final Map<String, String> passwordRequestBody = new HashMap<>();

    passwordRequestBody.put("name", credentialName);
    passwordRequestBody.put("type", "password");
    passwordRequestBody.put("value", passwordValue);

    final String content = JsonTestHelper.serializeToString(passwordRequestBody);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + token)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(content);

    return mockMvc.perform(put);
  }
}
