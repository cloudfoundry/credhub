package org.cloudfoundry.credhub.requests;

import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.ErrorMessages;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

public class PasswordSetRequestTest {
  @Test
  public void deserializesToPasswordSetRequest() {
    final String json = "{"
      + "\"name\":\"some-name\","
      + "\"type\":\"password\","
      + "\"value\":\"fake-password\""
      + "}";
    final PasswordSetRequest deserialize = deserialize(json, PasswordSetRequest.class);

    assertThat(deserialize, instanceOf(PasswordSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    final String json = "{"
      + "\"name\":\"some-name\","
      + "\"type\":\"password\","
      + "\"value\":\"fake-password\""
      + "}";
    final Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
      deserializeAndValidate(json, PasswordSetRequest.class);

    assertThat(constraintViolations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    final String json = "{"
      + "\"name\":\"some-name\","
      + "\"type\":\"PasSWorD\","
      + "\"value\":\"fake-password\""
      + "}";
    final Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
      deserializeAndValidate(json, PasswordSetRequest.class);

    assertThat(constraintViolations.size(), equalTo(0));
  }

  @Test
  public void whenPasswordIsNotSet_shouldBeInvalid() {
    final String json = "{"
      + "\"name\":\"some-name\","
      + "\"type\":\"password\""
      + "}";
    final Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
      deserializeAndValidate(json, PasswordSetRequest.class);

    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.MISSING_VALUE)));
  }

  @Test
  public void whenPasswordIsEmpty_shouldBeInvalid() {
    final String json = "{"
      + "\"name\":\"some-name\","
      + "\"type\":\"password\","
      + "\"value\":\"\""
      + "}";
    final Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
      deserializeAndValidate(json, PasswordSetRequest.class);

    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.MISSING_VALUE)));
  }
}
