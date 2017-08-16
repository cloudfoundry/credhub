package io.pivotal.security.request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNull;

@RunWith(JUnit4.class)
public class SshSetRequestTest {
  @Test
  public void deserializesToSshSetRequest() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"ssh\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    SshSetRequest deserialize = deserialize(json, SshSetRequest.class);

    assertThat(deserialize, instanceOf(SshSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"ssh\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void doesNotRequireThePublicKey() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"ssh\","
        + "\"value\": {"
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void doesNotRequireThePrivateKey() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"ssh\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"sSh\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenNoValueIsSet_shouldBeInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/ssh\",\n"
        + "  \"type\": \"ssh\"\n"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void whenValueIsEmpty_shouldBeInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/ssh\",\n"
        + "  \"type\": \"ssh\",\n"
        + "  \"value\": {}\n"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void whenAllValueSubFieldsAreEmpty_shouldBeInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/ssh\",\n"
        + "  \"type\": \"ssh\",\n"
        + "  \"value\": {"
        + "    \"public_key\":\"\","
        + "    \"private_key\":\"\""
        + "  }"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void whenAllValuesAreNull_shouldBeInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/ssh\",\n"
        + "  \"type\": \"ssh\",\n"
        + "  \"value\": {"
        + "    \"public_key\":null,"
        + "    \"private_key\":null"
        + "  }"
        + "}";
    Set<ConstraintViolation<SshSetRequest>> violations = deserializeAndValidate(json,
        SshSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void coercesEmptyPublicKeyIntoNull() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"ssh\","
        + "\"value\": {"
        + "\"public_key\":\"\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    SshSetRequest deserialize = deserialize(json, SshSetRequest.class);

    assertNull(deserialize.getSshKeyValue().getPublicKey());
  }

  @Test
  public void coercesEmptyPrivateKeyIntoNull() {
    String json = "{"
        + "\"name\": \"/example/ssh\","
        + "\"type\": \"ssh\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"\""
        + "}"
        + "}";
    SshSetRequest deserialize = deserialize(json, SshSetRequest.class);

    assertNull(deserialize.getSshKeyValue().getPrivateKey());
  }
}
