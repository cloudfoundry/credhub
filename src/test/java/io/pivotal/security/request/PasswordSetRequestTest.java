package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

@RunWith(Spectrum.class)
public class PasswordSetRequestTest {

  {
    it("should deserialize to PasswordSetRequest", () -> {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"password\","
          + "\"value\":\"fake-password\","
          + "\"overwrite\":true"
          + "}";
      PasswordSetRequest deserialize = deserialize(json, PasswordSetRequest.class);

      assertThat(deserialize, instanceOf(PasswordSetRequest.class));
    });

    it("should be valid if all fields are set", () -> {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"password\","
          + "\"value\":\"fake-password\","
          + "\"overwrite\":true"
          + "}";
      Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
          deserializeAndValidate(json, PasswordSetRequest.class);

      assertThat(constraintViolations.size(), equalTo(0));
    });
    describe("when type has unusual casing", () -> {
          it("should be valid", () -> {
            String json = "{"
                + "\"name\":\"some-name\","
                + "\"type\":\"PasSWorD\","
                + "\"value\":\"fake-password\","
                + "\"overwrite\":true"
                + "}";
            Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
                deserializeAndValidate(json, PasswordSetRequest.class);

            assertThat(constraintViolations.size(), equalTo(0));
          });
        });
    describe("when password is not set", () -> {
      it("should be invalid", () -> {
        String json = "{"
            + "\"name\":\"some-name\","
            + "\"type\":\"password\","
            + "\"overwrite\":true"
            + "}";
        Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
            deserializeAndValidate(json, PasswordSetRequest.class);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when password is empty", () -> {
      it("should be invalid", () -> {
        String json = "{"
            + "\"name\":\"some-name\","
            + "\"type\":\"password\","
            + "\"overwrite\":true,"
            + "\"value\":\"\""
            + "}";
        Set<ConstraintViolation<PasswordSetRequest>> constraintViolations =
            deserializeAndValidate(json, PasswordSetRequest.class);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });
  }
}
