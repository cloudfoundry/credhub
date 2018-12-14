package org.cloudfoundry.credhub.request;

import java.util.Set;

import javax.validation.ConstraintViolation;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNull;

@RunWith(JUnit4.class)
public class RsaSetRequestTest {


  @Test
  public void whenTheValueIsValid_itShouldNotHaveViolations() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"rsa\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_itShouldBeValid() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"RsA\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void shouldDeserializeToRSASetRequest() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"rsa\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

    assertThat(deserialize, instanceOf(RsaSetRequest.class));
  }

  @Test
  public void shouldNotRequirePublicKey() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"rsa\","
      + "\"value\": {"
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void shouldNotRequirePrivateKey() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"rsa\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\""
      + "}"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void shouldCoerceEmptyPublicKeyToNull() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"rsa\","
      + "\"value\": {"
      + "\"public_key\":\"\","
      + "\"private_key\":\"fake-private-key\""
      + "}"
      + "}";
    final RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

    assertNull(deserialize.getRsaKeyValue().getPublicKey());

  }

  @Test
  public void shouldCoerceEmptyPrivateKeyToNull() {
    final String json = "{"
      + "\"name\": \"/example/rsa\","
      + "\"type\": \"rsa\","
      + "\"value\": {"
      + "\"public_key\":\"fake-public-key\","
      + "\"private_key\":\"\""
      + "}"
      + "}";
    final RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

    assertNull(deserialize.getRsaKeyValue().getPrivateKey());
  }

  @Test
  public void shouldBeInvalid_whenValueIsNotSet() {
    final String json = "{\n"
      + "  \"name\": \"/example/rsa\",\n"
      + "  \"type\": \"rsa\"\n"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void shouldBeInvalid_whenValueIsAnEmptyObject() {
    final String json = "{\n"
      + "  \"name\": \"/example/rsa\",\n"
      + "  \"type\": \"rsa\",\n"
      + "  \"value\": {}\n"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations,
      contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void shouldBeInvalid_whenAllSubFieldsAreEmpty() {
    final String json = "{\n"
      + "  \"name\": \"/example/rsa\",\n"
      + "  \"type\": \"rsa\",\n"
      + "  \"value\": {"
      + "    \"public_key\":\"\","
      + "    \"private_key\":\"\""
      + "  }"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations,
      contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void shouldBeInvalid_whenRSAHasAllSubFieldsSetToNull() {
    final String json = "{\n"
      + "  \"name\": \"/example/rsa\",\n"
      + "  \"type\": \"rsa\",\n"
      + "  \"value\": {"
      + "    \"public_key\":null,"
      + "    \"private_key\":null"
      + "  }"
      + "}";
    final Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
      RsaSetRequest.class);

    assertThat(violations,
      contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }
}
