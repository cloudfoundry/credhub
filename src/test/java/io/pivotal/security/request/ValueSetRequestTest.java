package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import java.util.Set;
import javax.validation.ConstraintViolation;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class ValueSetRequestTest {

  {
    it("should deserialize to ValueSetRequest", () -> {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"value\","
          + "\"overwrite\":true,"
          + "\"value\":\"some-value\""
          + "}";
      BaseCredentialSetRequest request = deserialize(json, BaseCredentialSetRequest.class);

      assertThat(request, instanceOf(ValueSetRequest.class));
    });

    describe("when value is not set", () -> {
      it("should be invalid", () -> {
        String json = "{"
            + "\"name\":\"some-name\","
            + "\"type\":\"value\","
            + "\"overwrite\":true"
            + "}";
        ValueSetRequest valueSetRequest = (ValueSetRequest) deserialize(json,
            BaseCredentialSetRequest.class);
        Set<ConstraintViolation<ValueSetRequest>> violations = validate(valueSetRequest);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when value is empty", () -> {
      it("should be invalid", () -> {
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
      });
    });

    describe("when all fields are set", () -> {
      it("should be valid", () -> {
        String json = "{"
            + "\"name\":\"some-name\","
            + "\"type\":\"value\","
            + "\"overwrite\":true,"
            + "\"value\":\"some-value\""
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });
    });
  }
}
