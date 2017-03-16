package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.core.IsEqual.equalTo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;

@RunWith(Spectrum.class)
public class BaseSecretRequestTest {
  // We are using BaseSecretPutRequest as a concrete exemplar of the abstract BaseSecretRequest
  {
    describe("when given valid json", () -> {
      it("should be valid", () -> {
        String json = "{" +
            "\"type\":\"value\"," +
            "\"name\":\"some-name\"," + // it thinks this name has a slash in it
            "\"value\":\"some-value\"" +
            "}";
        Set<ConstraintViolation<BaseSecretPutRequest>> violations = deserializeAndValidate(json, BaseSecretPutRequest.class);
        assertThat(violations.size(), equalTo(0));
      });

      it("should set the correct fields", () -> {
        String json = "{" +
            "\"type\":\"value\"," +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"" +
          "}";
        BaseSecretPutRequest secretSetRequest = deserialize(json, BaseSecretPutRequest.class);

        assertThat(secretSetRequest.getType(), equalTo("value"));
        assertThat(secretSetRequest.getName(), equalTo("some-name"));
      });

      describe("#isOverwrite", () -> {
        it("should default to false", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"" +
            "}";
          BaseSecretPutRequest secretSetRequest = deserialize(json, BaseSecretPutRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(false));
        });

        it("should take the provided value if set", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
            "}";
          BaseSecretPutRequest secretSetRequest = deserialize(json, BaseSecretPutRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(true));
        });
      });
    });

    describe("validation", () -> {
      describe("when name ends with a slash", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"badname/\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretPutRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretPutRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a double slash", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"bad//name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretPutRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretPutRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a reDos attack", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretPutRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretPutRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretPutRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretPutRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when name is an empty string", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"\"," +
              "\"type\":\"value\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretPutRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretPutRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });
    });

    describe("access control entries", () -> {
      it("defaults to an empty list if not sent in the request", () -> {
        // language=JSON
        String json = "{\n" +
            "  \"name\": \"some-name\",\n" +
            "  \"type\": \"value\",\n" +
            "  \"value\": \"some-value\",\n" +
            "  \"overwrite\": true\n" +
            "}";

        final BaseSecretSetRequest request = JsonHelper.deserialize(json, BaseSecretSetRequest.class);
        assertThat(request.getAccessControlEntries(), empty());
      });

      it("should parse access control entry included in the request", () -> {
        // language=JSON
        String json = "{\n" +
            "  \"name\": \"some-name\",\n" +
            "  \"type\": \"value\",\n" +
            "  \"value\": \"some-value\",\n" +
            "  \"overwrite\": true,\n" +
            "  \"access_control_entries\": [\n" +
            "    {\n" +
            "      \"actor\": \"some-actor\",\n" +
            "      \"operations\": [\n" +
            "        \"read\",\n" +
            "        \"write\"\n" +
            "      ]\n" +
            "    }\n" +
            "  ]\n" +
            "}";
        final BaseSecretSetRequest request = JsonHelper.deserialize(json, BaseSecretSetRequest.class);

        final List<AccessControlOperation> operations = new ArrayList<>(Arrays.asList(AccessControlOperation.READ, AccessControlOperation.WRITE));
        final List<AccessControlEntry> expectedACEs = new ArrayList<>(Arrays.asList(new AccessControlEntry("some-actor", operations)));

        assertThat(request.getAccessControlEntries(), samePropertyValuesAs(expectedACEs));
      });
    });
  }
}
