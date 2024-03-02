package org.cloudfoundry.credhub.requests;

import java.io.IOException;
import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.core.IsEqual.equalTo;

public class UserSetRequestTest {
  private String validSetRequestJson;

  @BeforeEach
  public void beforeEach() {
    // language=JSON
    validSetRequestJson = "{\n" +
      "  \"name\": \"some-name\",\n" +
      "  \"type\": \"user\",\n" +
      "  \"value\": {\n" +
      "    \"username\": \"dan\",\n" +
      "    \"password\": \"example-password\"\n" +
      "  }\n" +
      "}";
  }

  @Test
  public void deserializesToUserSetRequest() throws IOException {
    final UserSetRequest userSetRequest = JsonTestHelper.deserializeChecked(validSetRequestJson, UserSetRequest.class);

    assertThat(userSetRequest, instanceOf(UserSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldHaveValidValueField() {
    final UserSetRequest userSetRequest = deserialize(validSetRequestJson, UserSetRequest.class);

    final UserCredentialValue userValue = userSetRequest.getUserValue();
    assert userValue != null;
    assertThat(userValue.getUsername(), equalTo("dan"));
    assertThat(userValue.getPassword(), equalTo("example-password"));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    final Set<ConstraintViolation<UserSetRequest>> violations = deserializeAndValidate(validSetRequestJson,
      UserSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    // language=JSON
    final String json = "{\n" +
      "  \"name\": \"some-name\",\n" +
      "  \"type\": \"UseR\",\n" +
      "  \"value\": {\n" +
      "    \"username\": \"dan\",\n" +
      "    \"password\": \"example-password\"\n" +
      "  }\n" +
      "}";
    final Set<ConstraintViolation<UserSetRequest>> violations = deserializeAndValidate(json, UserSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenValueIsEmpty_shouldBeInvalid() {
    // language=JSON
    final String json = "{\n" +
      "  \"name\": \"some-name\",\n" +
      "  \"type\": \"user\"" +
      "}";
    final UserSetRequest userSetRequest = deserialize(json,
      UserSetRequest.class);
    final Set<ConstraintViolation<UserSetRequest>> violations = validate(userSetRequest);

    assertThat(violations, contains(hasViolationWithMessage(ErrorMessages.MISSING_VALUE)));
  }

  @Test
  public void whenPasswordIsNotSetInRequest_shouldBeInvalid() {
    final String invalidSetRequestJson = "{\n" +
      "  \"name\": \"some-name\",\n" +
      "  \"type\": \"user\",\n" +
      "  \"value\": {\n" +
      "    \"username\": \"dan\"\n" +
      "  }\n" +
      "}";

    final Set<ConstraintViolation<UserSetRequest>> violations = deserializeAndValidate(invalidSetRequestJson, UserSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage(ErrorMessages.MISSING_PASSWORD)));
  }
}
