package org.cloudfoundry.credhub.requests;

import java.io.IOException;
import java.util.Set;

import jakarta.validation.ConstraintViolation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

public class JsonSetRequestTest {
  @Test
  public void deserializesToJsonSetRequest() {
    final String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
      + "\"type\":\"json\","
      + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]}}";

    final JsonSetRequest deserialize = deserialize(requestJson, JsonSetRequest.class);

    assertThat(deserialize, instanceOf(JsonSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    final String jsonString = "{\"foo\":\"bar\",\"nested\":{\"key\":3}}";
    final JsonNode value;
    try {
      value = new ObjectMapper().readTree(jsonString);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }

    final JsonSetRequest request = new JsonSetRequest();
    request.setName("some-name");
    request.setType("json");
    request.setValue(new JsonCredentialValue(value));

    final Set<ConstraintViolation<JsonSetRequest>> constraintViolations = validate(request);

    assertThat(constraintViolations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    final String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
      + "\"type\":\"JsOn\","
      + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]}}";

    final Set<ConstraintViolation<JsonSetRequest>> constraintViolations = deserializeAndValidate(requestJson, JsonSetRequest.class);

    assertThat(constraintViolations.size(), equalTo(0));
  }

  @Test
  public void whenValueIsNotSet_shouldBeInvalid() {
    final JsonSetRequest request = new JsonSetRequest();
    request.setName("some-name");
    request.setType("json");

    final Set<ConstraintViolation<JsonSetRequest>> constraintViolations = validate(request);

    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.MISSING_VALUE)));
  }
}
