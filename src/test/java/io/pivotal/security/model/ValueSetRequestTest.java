package io.pivotal.security.model;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.ValueSetRequest;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class ValueSetRequestTest {
  {
    describe("when value is not set", () -> {
      it("should be invalid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"value\"," +
            "\"overwrite\":true" +
            "}";
        ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json, BaseSecretSetRequest.class);
        Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

        assertThat(violations, contains(hasViolationWithMessage("value may not be empty")));
      });
    });

    describe("when value is empty", () -> {
      it("should be invalid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"value\"," +
            "\"overwrite\":true," +
            "\"value\":\"\"" +
            "}";
        ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json, BaseSecretSetRequest.class);
        Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

        assertThat(violations, contains(hasViolationWithMessage("value may not be empty")));
      });
    });

    describe("when all fields are set", () -> {
      it("should be valid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"value\"," +
            "\"overwrite\":true," +
            "\"value\":\"some-value\"" +
            "}";
        ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json, BaseSecretSetRequest.class);
        Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

        assertThat(violations.size(), equalTo(0));
      });
    });
  }
}
