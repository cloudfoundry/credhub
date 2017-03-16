package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
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
public class SshSetRequestTest {
  {
    describe("when the value is valid", () -> {
      it("should not have violations", () -> {
        String json = "{" +
            "\"name\": \"/example/ssh\"," +
            "\"type\": \"ssh\"," +
            "\"value\": {" +
              "\"public_key\":\"fake-public-key\"," +
              "\"private_key\":\"fake-private-key\"" +
            "}" +
          "}";
        Set<ConstraintViolation<BaseSecretPutRequest>> violations = deserializeAndValidate(json, BaseSecretPutRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should should deserialize to a SshSetRequest", () -> {
        String json = "{" +
            "\"name\": \"/example/ssh\"," +
            "\"type\": \"ssh\"," +
            "\"value\": {" +
              "\"public_key\":\"fake-public-key\"," +
              "\"private_key\":\"fake-private-key\"" +
            "}" +
          "}";
        BaseSecretPutRequest deserialize = deserialize(json, BaseSecretPutRequest.class);

        assertThat(deserialize, instanceOf(SshSetRequest.class));

      });
    });

    describe("when no value is set", () -> {
      it("should be in invalid", () -> {
        String json = "{\n" +
          "  \"name\": \"/example/ssh\",\n" +
          "  \"type\": \"ssh\"\n" +
          "}";
        Set<ConstraintViolation<BaseSecretPutRequest>> violations = deserializeAndValidate(json, BaseSecretPutRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when value is an empty object", () -> {
      it("should be invalid", () -> {
        String json = "{\n" +
          "  \"name\": \"/example/ssh\",\n" +
          "  \"type\": \"ssh\",\n" +
          "  \"value\": {}\n" +
          "}";
        Set<ConstraintViolation<BaseSecretPutRequest>> violations = deserializeAndValidate(json, BaseSecretPutRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
      });
    });

    describe("when ssh has all null sub-fields", () -> {
      it("should be invalid", () -> {
        String json = "{\n" +
          "  \"name\": \"/example/ssh\",\n" +
          "  \"type\": \"ssh\",\n" +
          "  \"value\": {" +
          "    \"public_key\":\"\"," +
          "    \"private_key\":\"\"" +
          "  }" +
          "}";
        Set<ConstraintViolation<BaseSecretPutRequest>> violations = deserializeAndValidate(json, BaseSecretPutRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
      });
    });
  }
}
