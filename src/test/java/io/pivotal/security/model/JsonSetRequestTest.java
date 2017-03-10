package io.pivotal.security.model;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.JsonSetRequest;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.serialize;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

@RunWith(Spectrum.class)
public class JsonSetRequestTest {
  {
    it("should deserialize to JsonSetRequest", () -> {
      Map<String, Object> nested = new HashMap<>();
      nested.put("key", 3);

      Map<String, Object> value = new HashMap<>();
      value.put("foo", "bar");
      value.put("nested", nested);

      JsonSetRequest request = new JsonSetRequest();
      request.setName("some-name");
      request.setType("json");
      request.setValue(value);
      request.setOverwrite(true);

      BaseSecretSetRequest deserialize = deserialize(serialize(request), BaseSecretSetRequest.class);

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
      request.setValue(value);
      request.setOverwrite(true);

      Set<ConstraintViolation<BaseSecretSetRequest>> constraintViolations = validate(request);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    describe("when value is not set", () -> {
      it("should be invalid", () -> {
        JsonSetRequest request = new JsonSetRequest();
        request.setName("some-name");
        request.setType("json");
        request.setOverwrite(true);

        Set<ConstraintViolation<BaseSecretSetRequest>> constraintViolations = validate(request);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });
  }
}
