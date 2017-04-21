package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class BaseCredentialRequestTest {

  // We are using BaseCredentialSetRequest as a concrete exemplar of the abstract BaseCredentialRequest
  {
    describe("when given valid json", () -> {
      it("should be valid", () -> {
        // language=JSON
        String json = "{"
            + "\"type\":\"value\","
            + "\"name\":\"some-name\","
            + /* it thinks this name has a slash in it*/ "\"value\":\"some-value\""
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);
        assertThat(violations.size(), equalTo(0));
      });

      it("should set the correct fields", () -> {
        // language=JSON
        String json = "{"
            + "\"type\":\"value\","
            + "\"name\":\"some-name\","
            + "\"value\":\"some-value\""
            + "}";
        BaseCredentialSetRequest credentialSetRequest = deserialize(json, BaseCredentialSetRequest.class);

        assertThat(credentialSetRequest.getType(), equalTo("value"));
        assertThat(credentialSetRequest.getName(), equalTo("some-name"));
      });

      describe("#isOverwrite", () -> {
        it("should default to false", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"name\":\"some-name\","
              + "\"value\":\"some-value\""
              + "}";
          BaseCredentialSetRequest credentialSetRequest = deserialize(json, BaseCredentialSetRequest.class);

          assertThat(credentialSetRequest.isOverwrite(), equalTo(false));
        });

        it("should take the provided value if set", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"name\":\"some-name\","
              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          BaseCredentialSetRequest credentialSetRequest = deserialize(json, BaseCredentialSetRequest.class);

          assertThat(credentialSetRequest.isOverwrite(), equalTo(true));
        });
      });
    });

    describe("validation", () -> {
      describe("when name ends with a slash", () -> {
        it("should be invalid", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"name\":\"badname/\","
              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonHelper
              .deserializeAndValidate(json, BaseCredentialSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a double slash", () -> {
        it("should be invalid", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"name\":\"bad//name\","
              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonHelper
              .deserializeAndValidate(json, BaseCredentialSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a reDos attack", () -> {
        it("should be invalid", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"name\":\"/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/"
              + "com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/"
              + "com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/"
              + "com/foo/com/foo/com/\","

              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonHelper
              .deserializeAndValidate(json, BaseCredentialSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name is not set", () -> {
        it("should be invalid", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonHelper
              .deserializeAndValidate(json, BaseCredentialSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when name is an empty string", () -> {
        it("should be invalid", () -> {
          // language=JSON
          String json = "{"
              + "\"name\":\"\","
              + "\"type\":\"value\","
              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonHelper
              .deserializeAndValidate(json, BaseCredentialSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when name contains a '.' character", () -> {
        it("should be valid", () -> {
          // language=JSON
          String json = "{"
              + "\"type\":\"value\","
              + "\"name\":\"test.name/\","
              + "\"value\":\"some-value\","
              + "\"overwrite\":true"
              + "}";
          Set<ConstraintViolation<BaseCredentialSetRequest>> violations = JsonHelper
              .deserializeAndValidate(json, BaseCredentialSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });
    });

    describe("access control entries", () -> {
      it("defaults to an empty list if not sent in the request", () -> {
        // language=JSON
        String json = "{ \"name\": \"some-name\",\n"
            + "  \"type\": \"value\",\n"
            + "  \"value\": \"some-value\",\n"
            + "  \"overwrite\": true\n"
            + "}";

        final BaseCredentialSetRequest request = JsonHelper
            .deserialize(json, BaseCredentialSetRequest.class);
        assertThat(request.getAccessControlEntries(), empty());
      });

      it("should parse access control entry included in the request", () -> {
        // language=JSON
        String json = "{\n"
            + "  \"name\": \"some-name\",\n"
            + "  \"type\": \"value\",\n"
            + "  \"value\": \"some-value\",\n"
            + "  \"overwrite\": true,\n"
            + "  \"access_control_entries\": [\n"
            + "    {\n"
            + "      \"actor\": \"some-actor\",\n"
            + "      \"operations\": [\n"
            + "        \"read\",\n"
            + "        \"write\"\n"
            + "      ]\n"
            + "    }\n"
            + "  ]\n"
            + "}";
        final BaseCredentialSetRequest request = JsonHelper
            .deserialize(json, BaseCredentialSetRequest.class);

        final List<AccessControlOperation> operations = new ArrayList<>(
            Arrays.asList(AccessControlOperation.READ, AccessControlOperation.WRITE));
        final List<AccessControlEntry> expectedAces = new ArrayList<>(
            Arrays.asList(new AccessControlEntry("some-actor", operations)));

        assertThat(request.getAccessControlEntries(), samePropertyValuesAs(expectedAces));
      });
    });

    describe("#validate", () -> {
      itThrowsWithMessage("throws with error.invalid_name_has_slash",
          ParameterizedValidationException.class, "error.invalid_name_has_slash", () -> {
            // language=JSON
            String json = "{\n"
                + "  \"name\": \"//some-name\",\n"
                + "  \"type\": \"value\",\n"
                + "  \"value\": \"some-value\"\n"
                + "}";
            final BaseCredentialSetRequest request = JsonHelper
                .deserialize(json, BaseCredentialSetRequest.class);
            request.validate();
          });
    });
  }
}
