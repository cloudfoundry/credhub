package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class UserSetRequestTest {
  private String validSetRequestJson;

  @Before
  public void beforeEach() {
    // language=JSON
    validSetRequestJson = "{\n" +
        "  \"name\": \"some-name\",\n" +
        "  \"type\": \"user\",\n" +
        "  \"overwrite\": true,\n" +
        "  \"value\": {\n" +
        "    \"username\": \"dan\",\n" +
        "    \"password\": \"example-password\"\n" +
        "  }\n" +
        "}";
  }

  @Test
  public void deserializesToUserSetRequest() throws IOException {
    UserSetRequest userSetRequest = JsonTestHelper.deserializeChecked(validSetRequestJson, UserSetRequest.class);

    assertThat(userSetRequest, instanceOf(UserSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldHaveValidValueField() {
    UserSetRequest userSetRequest = JsonTestHelper.deserialize(validSetRequestJson, UserSetRequest.class);

    UserCredentialValue userValue = userSetRequest.getUserValue();
    assertThat(userValue.getUsername(), equalTo("dan"));
    assertThat(userValue.getPassword(), equalTo("example-password"));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    Set<ConstraintViolation<UserSetRequest>> violations = deserializeAndValidate(validSetRequestJson,
        UserSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    // language=JSON
    String json = "{\n" +
        "  \"name\": \"some-name\",\n" +
        "  \"type\": \"UseR\",\n" +
        "  \"overwrite\": true,\n" +
        "  \"value\": {\n" +
        "    \"username\": \"dan\",\n" +
        "    \"password\": \"example-password\"\n" +
        "  }\n" +
        "}";
    Set<ConstraintViolation<UserSetRequest>> violations = deserializeAndValidate(json, UserSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenValueIsEmpty_shouldBeInvalid() {
    // language=JSON
    String json = "{\n" +
        "  \"name\": \"some-name\",\n" +
        "  \"type\": \"user\",\n" +
        "  \"overwrite\": true\n" +
        "}";
    UserSetRequest userSetRequest = deserialize(json,
        UserSetRequest.class);
    Set<ConstraintViolation<UserSetRequest>> violations = validate(userSetRequest);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void whenPasswordIsNotSetInRequest_shouldBeInvalid() {
    String invalidSetRequestJson = "{\n" +
        "  \"name\": \"some-name\",\n" +
        "  \"type\": \"user\",\n" +
        "  \"overwrite\": true,\n" +
        "  \"value\": {\n" +
        "    \"username\": \"dan\"\n" +
        "  }\n" +
        "}";

    Set<ConstraintViolation<UserSetRequest>> violations = JsonTestHelper.deserializeAndValidate(invalidSetRequestJson, UserSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_password")));
  }
}
