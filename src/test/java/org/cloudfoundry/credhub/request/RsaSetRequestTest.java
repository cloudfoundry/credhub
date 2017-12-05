package org.cloudfoundry.credhub.request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

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
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"rsa\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_itShouldBeValid() {
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"RsA\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void shouldDeserializeToRSASetRequest() {
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"rsa\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

    assertThat(deserialize, instanceOf(RsaSetRequest.class));
  }

  @Test
  public void shouldNotRequirePublicKey() {
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"rsa\","
        + "\"value\": {"
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void shouldNotRequirePrivateKey() {
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"rsa\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\""
        + "}"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void shouldCoerceEmptyPublicKeyToNull() {
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"rsa\","
        + "\"value\": {"
        + "\"public_key\":\"\","
        + "\"private_key\":\"fake-private-key\""
        + "}"
        + "}";
    RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

    assertNull(deserialize.getRsaKeyValue().getPublicKey());

  }

  @Test
  public void shouldCoerceEmptyPrivateKeyToNull() {
    String json = "{"
        + "\"name\": \"/example/rsa\","
        + "\"type\": \"rsa\","
        + "\"value\": {"
        + "\"public_key\":\"fake-public-key\","
        + "\"private_key\":\"\""
        + "}"
        + "}";
    RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

    assertNull(deserialize.getRsaKeyValue().getPrivateKey());
  }

  @Test
  public void shouldBeInvalid_whenValueIsNotSet() {
    String json = "{\n"
        + "  \"name\": \"/example/rsa\",\n"
        + "  \"type\": \"rsa\"\n"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void shouldBeInvalid_whenValueIsAnEmptyObject() {
    String json = "{\n"
        + "  \"name\": \"/example/rsa\",\n"
        + "  \"type\": \"rsa\",\n"
        + "  \"value\": {}\n"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void shouldBeInvalid_whenAllSubFieldsAreEmpty() {
    String json = "{\n"
        + "  \"name\": \"/example/rsa\",\n"
        + "  \"type\": \"rsa\",\n"
        + "  \"value\": {"
        + "    \"public_key\":\"\","
        + "    \"private_key\":\"\""
        + "  }"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }

  @Test
  public void shouldBeInvalid_whenRSAHasAllSubFieldsSetToNull() {
    String json = "{\n"
        + "  \"name\": \"/example/rsa\",\n"
        + "  \"type\": \"rsa\",\n"
        + "  \"value\": {"
        + "    \"public_key\":null,"
        + "    \"private_key\":null"
        + "  }"
        + "}";
    Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
        RsaSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
  }
}
