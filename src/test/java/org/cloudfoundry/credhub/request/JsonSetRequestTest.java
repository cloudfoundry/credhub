package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.credential.JsonCredentialValue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

@RunWith(JUnit4.class)
public class JsonSetRequestTest {
  @Test
  public void deserializesToJsonSetRequest() {
    String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
        + "\"type\":\"json\","
        + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]},"
        + "\"overwrite\":false,"
        + "\"additional_permissions\": [{\"actor\": \"app1-guid\",\"operations\": [\"read\"]}]}";

    JsonSetRequest deserialize = deserialize(requestJson,
        JsonSetRequest.class);

    assertThat(deserialize, instanceOf(JsonSetRequest.class));
  }

  @Test
  public void whenAllFieldsAreSet_shouldBeValid() {
    Map<String, Object> nested = new HashMap<>();
    nested.put("key", 3);

    Map<String, Object> value = new HashMap<>();
    value.put("foo", "bar");
    value.put("nested", nested);

    JsonSetRequest request = new JsonSetRequest();
    request.setName("some-name");
    request.setType("json");
    request.setValue(new JsonCredentialValue(value));
    request.setOverwrite(true);

    Set<ConstraintViolation<JsonSetRequest>> constraintViolations = validate(request);

    assertThat(constraintViolations.size(), equalTo(0));
  }

  @Test
  public void whenTypeHasUnusualCasing_shouldBeValid() {
    String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
        + "\"type\":\"JsOn\","
        + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]},"
        + "\"overwrite\":false,"
        + "\"additional_permissions\": [{\"actor\": \"app1-guid\",\"operations\": [\"read\"]}]}";

    Set<ConstraintViolation<JsonSetRequest>> constraintViolations = deserializeAndValidate(requestJson, JsonSetRequest.class);

    assertThat(constraintViolations.size(), equalTo(0));
  }

  @Test
  public void whenValueIsNotSet_shouldBeInvalid() {
    JsonSetRequest request = new JsonSetRequest();
    request.setName("some-name");
    request.setType("json");
    request.setOverwrite(true);

    Set<ConstraintViolation<JsonSetRequest>> constraintViolations = validate(request);

    assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
  }
}
