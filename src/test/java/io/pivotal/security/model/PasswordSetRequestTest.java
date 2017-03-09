package io.pivotal.security.model;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

@RunWith(Spectrum.class)
public class PasswordSetRequestTest {
  {
    it("should deserialize to PasswordSetRequest", () -> {
      String json = "{" +
        "\"name\":\"some-name\"," +
        "\"type\":\"password\"," +
        "\"value\":\"fake-password\"," +
        "\"overwrite\":true" +
        "}";
      BaseSecretSetRequest deserialize = deserialize(json, BaseSecretSetRequest.class);

      assertThat(deserialize, instanceOf(PasswordSetRequest.class));
    });

    it("should be valid if all fields are set", () -> {
      String json = "{" +
        "\"name\":\"some-name\"," +
        "\"type\":\"password\"," +
        "\"value\":\"fake-password\"," +
        "\"overwrite\":true" +
        "}";
      Set<ConstraintViolation<BaseSecretSetRequest>> constraintViolations = deserializeAndValidate(json, BaseSecretSetRequest.class);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    describe("when password is not set", () -> {
      it("should be invalid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"password\"," +
            "\"overwrite\":true" +
            "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> constraintViolations = deserializeAndValidate(json, BaseSecretSetRequest.class);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when password is empty", () -> {
      it("should be invalid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"password\"," +
            "\"overwrite\":true," +
            "\"value\":\"\"" +
            "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> constraintViolations = deserializeAndValidate(json, BaseSecretSetRequest.class);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });
  }
}
