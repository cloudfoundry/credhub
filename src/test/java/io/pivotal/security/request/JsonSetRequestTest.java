package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.credential.JsonCredentialValue;
import org.junit.runner.RunWith;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonTestHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

@RunWith(Spectrum.class)
public class JsonSetRequestTest {

  {
    it("should deserialize to JsonSetRequest", () -> {
      String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
          + "\"type\":\"json\","
          + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]},"
          + "\"overwrite\":false,"
          + "\"additional_permissions\": [{\"actor\": \"app1-guid\",\"operations\": [\"read\"]}]}";

      JsonSetRequest deserialize = deserialize(requestJson,
          JsonSetRequest.class);

      assertThat(deserialize, instanceOf(JsonSetRequest.class));
    });

    it("should be valid if all fields are set", () -> {
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
    });

    describe("when type has unusual casing", () ->{
      it("should be valid", () -> {
        String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
            + "\"type\":\"JsOn\","
            + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]},"
            + "\"overwrite\":false,"
            + "\"additional_permissions\": [{\"actor\": \"app1-guid\",\"operations\": [\"read\"]}]}";

        Set<ConstraintViolation<JsonSetRequest>> constraintViolations = deserializeAndValidate(requestJson, JsonSetRequest.class);

        assertThat(constraintViolations.size(), equalTo(0));
      });
    });

    describe("when value is not set", () -> {
      it("should be invalid", () -> {
        JsonSetRequest request = new JsonSetRequest();
        request.setName("some-name");
        request.setType("json");
        request.setOverwrite(true);

        Set<ConstraintViolation<JsonSetRequest>> constraintViolations = validate(request);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });
  }
}
