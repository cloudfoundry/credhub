package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class BaseSecretSetRequestTest {
  {
    describe("when given valid json", () -> {
      it("should be valid", () -> {
        String json = "{" +
            "\"type\":\"value\"," +
            "\"name\":\"some-name\"," + // it thinks this name has a slash in it
            "\"value\":\"some-value\"" +
            "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(json, BaseSecretSetRequest.class);
        assertThat(violations.size(), equalTo(0));
      });

      it("should set the correct fields", () -> {
        String json = "{" +
            "\"type\":\"some-type\"," +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"" +
          "}";
        BaseSecretSetRequest secretSetRequest = deserialize(json, BaseSecretSetRequest.class);

        assertThat(secretSetRequest.getType(), equalTo("some-type"));
        assertThat(secretSetRequest.getName(), equalTo("some-name"));
      });

      describe("#isOverwrite", () -> {
        it("should default to false", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"" +
            "}";
          BaseSecretSetRequest secretSetRequest = deserialize(json, BaseSecretSetRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(false));
        });

        it("should take the provide value if set", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
            "}";
          BaseSecretSetRequest secretSetRequest = deserialize(json, BaseSecretSetRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(true));
        });
      });
    });

    describe("validation", () -> {
      describe("when name ends with a slash", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"badname/\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a double slash", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"bad//name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a reDos attack", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when name is an empty string", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"\"," +
              "\"type\":\"some-type\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when type is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.type_invalid")));
        });
      });

      describe("when type is an empty string", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"type\":\"\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.type_invalid")));
        });
      });
    });
  }
}
