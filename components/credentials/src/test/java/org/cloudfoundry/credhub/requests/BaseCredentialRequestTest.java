package org.cloudfoundry.credhub.requests;

import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.hamcrest.MatcherAssert;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static junit.framework.TestCase.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class BaseCredentialRequestTest {
  @Test
  public void whenGivenValidJson_shouldBeValid() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"/some/NAME/with_all-valid_CHARACTERS/0123456789\","
      + /* it thinks this name has a slash in it*/ "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      BaseCredentialSetRequest.class);
    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenGivenModeAttribute_shouldBeValid() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"/some/NAME/with_all-valid_CHARACTERS/0123456789\","
      + /* it thinks this name has a slash in it*/ "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      BaseCredentialSetRequest.class);
    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenGivenValidJson_setsCorrectFields() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"/some-name\","
      + "\"value\":\"some-value\""
      + "}";
    final BaseCredentialSetRequest credentialSetRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);

    assertThat(credentialSetRequest.getType(), equalTo("value"));
    assertThat(credentialSetRequest.getName(), equalTo("/some-name"));
  }

  @Test
  public void setName_whenNameDoesNotStartWithASlash_prependsASlash() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"some-name\","
      + "\"value\":\"some-value\""
      + "}";
    final BaseCredentialSetRequest credentialSetRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);

    assertThat(credentialSetRequest.getType(), equalTo("value"));
    assertThat(credentialSetRequest.getName(), equalTo("/some-name"));
  }


  @Test
  public void whenNameEndsWithSlash_shouldBeInvalid() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"badname/\","
      + "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
      .deserializeAndValidate(json, BaseCredentialSetRequest.class);

    MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(
      ErrorMessages.Credential.INVALID_SLASH_IN_NAME)));
  }

  @Test
  public void whenNameContainsDoubleSlash_shouldBeInvalid() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"bad//name\","
      + "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
      .deserializeAndValidate(json, BaseCredentialSetRequest.class);

    MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.Credential.INVALID_SLASH_IN_NAME)));
  }

  @Test
  public void whenNameContainsReDosAttack_shouldBeInvalid() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"name\":\"/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/"
      + "com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/"
      + "com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/"
      + "com/foo/com/foo/com/\","

      + "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
      .deserializeAndValidate(json, BaseCredentialSetRequest.class);

    MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.Credential.INVALID_SLASH_IN_NAME)));
  }

  @Test
  public void whenNameIsNotSet_shouldBeInvalid() {
    // language=JSON
    final String json = "{"
      + "\"type\":\"value\","
      + "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
      .deserializeAndValidate(json, BaseCredentialSetRequest.class);

    MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.MISSING_NAME)));
  }

  @Test
  public void whenNameIsEmpty_shouldBeInvalid() {
    // language=JSON
    final String json = "{"
      + "\"name\":\"\","
      + "\"type\":\"value\","
      + "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
      .deserializeAndValidate(json, BaseCredentialSetRequest.class);

    MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.MISSING_NAME)));
  }

  @Test
  public void whenNameIsJustASlash_shouldBeInvalid() {
    // language=JSON
    final String json = "{"
      + "\"name\":\"/\","
      + "\"type\":\"value\","
      + "\"value\":\"some-value\""
      + "}";
    final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
      .deserializeAndValidate(json, BaseCredentialSetRequest.class);

    MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.MISSING_NAME)));
  }

  @Test
  public void whenNameContainsInvalidCharacter_shouldBeInvalid() {
    for (final char invalidCharacter : new char[]{' ', '\\', '*'}) {
      // language=JSON
      final String json = "{"
        + "\"type\":\"value\","
        + "\"name\":\"test" + invalidCharacter + "name\","
        + "\"value\":\"some-value\""
        + "}";
      final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
        .deserializeAndValidate(json, BaseCredentialSetRequest.class);

      MatcherAssert.assertThat(violations, IsIterableContainingInOrder.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.Credential.INVALID_CHARACTER_IN_NAME)));
    }
  }

  @Test
  public void whenNameContainsSpecialCharacters_shouldBeValid() {

    for (final char specialCharacter : new char[]{'.', ':', '(', ')', '[', ']', '+'}) {
      // language=JSON
      final String json = "{"
        + "\"type\":\"value\","
        + "\"name\":\"test" + specialCharacter + "name\","
        + "\"value\":\"some-value\""
        + "}";
      final Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonTestHelper
        .deserializeAndValidate(json, BaseCredentialSetRequest.class);

      MatcherAssert.assertThat(violations.size(), equalTo(0));
    }
  }

  @Test
  public void validate_throwsWhenNameHasInvalidSlash() {
    // language=JSON
    final String json = "{\n"
      + "  \"name\": \"//some-name\",\n"
      + "  \"type\": \"value\",\n"
      + "  \"value\": \"some-value\"\n"
      + "}";
    final BaseCredentialSetRequest request = JsonTestHelper
      .deserialize(json, BaseCredentialSetRequest.class);

    try {
      request.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_SLASH_IN_NAME));
    }
  }
}
