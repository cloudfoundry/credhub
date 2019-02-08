package org.cloudfoundry.credhub.requests;

import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNull;

@RunWith(JUnit4.class)
public class SshSetRequestTest {
  @Test
  public void deserializesToSshSetRequest() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"ssh\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final SshSetRequest deserialize = JsonTestHelper.deserialize(json, SshSetRequest.class);

    assertThat(deserialize, instanceOf(SshSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"ssh\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void doesNotRequireThePublicKey() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"ssh\","
      + "\"value\": {"
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void doesNotRequireThePrivateKey() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"ssh\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"sSh\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenNoValueIsSet_shouldBeInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/ssh\",\n"
      + "  \"type\": \"ssh\"\n"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void whenValueIsEmpty_shouldBeInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/ssh\",\n"
      + "  \"type\": \"ssh\",\n"
      + "  \"value\": {}\n"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    MatcherAssert.assertThat(violations,
      Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void whenAllValueSubFieldsAreEmpty_shouldBeInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/ssh\",\n"
      + "  \"type\": \"ssh\",\n"
      + "  \"value\": {"
      + "    \"public_key\":\"\","
      + "    \"private_key\":\"\""
      + "  }"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    MatcherAssert.assertThat(violations,
      Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void whenAllValuesAreNull_shouldBeInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/ssh\",\n"
      + "  \"type\": \"ssh\",\n"
      + "  \"value\": {"
      + "    \"public_key\":null,"
      + "    \"private_key\":null"
      + "  }"
      + "}";
    final Set<ConstraintViolation<SshSetRequest>> violations = JsonTestHelper.deserializeAndValidate(json,
      SshSetRequest.class);

    MatcherAssert.assertThat(violations,
      Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void coercesEmptyPublicKeyIntoNull() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"ssh\","
      + "\"value\": {"
      + "\"public_key\":\"\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final SshSetRequest deserialize = JsonTestHelper.deserialize(json, SshSetRequest.class);

    assertNull(deserialize.getSshKeyValue().getPublicKey());
  }

  @Test
  public void coercesEmptyPrivateKeyIntoNull() {
    final String json = "{"
      + "\"name\": \"/example/ssh\","
      + "\"type\": \"ssh\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"\""
      + "}"
      + "}";
    final SshSetRequest deserialize = JsonTestHelper.deserialize(json, SshSetRequest.class);

    assertNull(deserialize.getSshKeyValue().getPrivateKey());
  }
}
