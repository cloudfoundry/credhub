package org.cloudfoundry.credhub.request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.validate;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class ValueSetRequestTest {
  @Test
  public void deserializesToValueSetRequest() {
    String json = "{"
        + "\"name\":\"some-name\","
        + "\"type\":\"value\","
        + "\"overwrite\":true,"
        + "\"value\":\"some-value\""
        + "}";
    BaseCredentialSetRequest request = deserialize(json, BaseCredentialSetRequest.class);

    assertThat(request, instanceOf(ValueSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    String json = "{"
        + "\"name\":\"some-name\","
        + "\"type\":\"value\","
        + "\"overwrite\":true,"
        + "\"value\":\"some-value\""
        + "}";
    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    String json = "{"
        + "\"name\":\"some-name\","
        + "\"type\":\"VaLuE\","
        + "\"overwrite\":true,"
        + "\"value\":\"some-value\""
        + "}";
    ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json,
        BaseCredentialSetRequest.class);
    Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenValueIsNotSet_shouldBeInvalid() {
    String json = "{"
        + "\"name\":\"some-name\","
        + "\"type\":\"value\","
        + "\"overwrite\":true"
        + "}";
    ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json,
        BaseCredentialSetRequest.class);
    Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void whenValueIsEmpty_shouldBeInvalid() {
    String json = "{"
        + "\"name\":\"some-name\","
        + "\"type\":\"value\","
        + "\"overwrite\":true,"
        + "\"value\":\"\""
        + "}";
    ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json,
        BaseCredentialSetRequest.class);
    Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }
}
