package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserialize;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class UserGenerateRequestTest {

  @Test
  public void getUsername_whenUsernameIsInParams_shouldReturnUsername() {
    String json = "{"
        + "\"name\": \"/example/user\","
        + "\"type\": \"user\","
        + "\"parameters\": {"
        + "\"username\":\"darth-vader\","
        + "\"exclude_lower\":\"true\""
        + "}"
        + "}";

    UserGenerateRequest deserialize = (UserGenerateRequest) JsonTestHelper
        .deserialize(json, BaseCredentialGenerateRequest.class);

    assertThat(deserialize, instanceOf(UserGenerateRequest.class));
    assertThat(deserialize.getUserName(), equalTo("darth-vader"));
  }

  @Test
  public void getUsername_whenUsernameIsInValue_shouldReturnUsername() {
    String json = "{"
        + "\"name\": \"/example/user\","
        + "\"type\": \"user\","
        + "\"value\": {"
        + "\"username\":\"darth-vader\""
        + "}"
        + "}";

    UserGenerateRequest deserialize = (UserGenerateRequest) JsonTestHelper
        .deserialize(json, BaseCredentialGenerateRequest.class);

    assertThat(deserialize, instanceOf(UserGenerateRequest.class));
    assertThat(deserialize.getUserName(), equalTo("darth-vader"));
  }

  @Test
  public void getUsername_whenUsernameIsInBothValueAndParameters_prefersParameters() {
    String json = "{"
        + "\"name\": \"/example/user\","
        + "\"type\": \"user\","
        + "\"parameters\": {"
        + "\"username\":\"darth-vader\""
        + "},"
        + "\"value\": {"
        + "\"username\":\"fnu\""
        + "}"
        + "}";

    UserGenerateRequest deserialize = (UserGenerateRequest) JsonTestHelper
        .deserialize(json, BaseCredentialGenerateRequest.class);

    assertThat(deserialize, instanceOf(UserGenerateRequest.class));
    assertThat(deserialize.getUserName(), equalTo("darth-vader"));
  }
}
