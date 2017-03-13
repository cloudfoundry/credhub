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
public class CertificateSetRequestTest {
  {
    describe("when the value is valid", () -> {
      it("should not have violations", () -> {
        String json = "{" +
            "\"name\": \"/example/certificate\"," +
            "\"type\": \"certificate\"," +
            "\"value\": {" +
              "\"certificate\":\"fake-certificate\"," +
              "\"private_key\":\"fake-private-key\"," +
              "\"ca\":\"fake-ca\"" +
            "}" +
          "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(json, BaseSecretSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should should deserialize to a CertificateSetRequest", () -> {
        String json = "{" +
            "\"name\": \"/example/certificate\"," +
            "\"type\": \"certificate\"," +
            "\"value\": {" +
              "\"certificate\":\"fake-certificate\"," +
              "\"private_key\":\"fake-private_key\"," +
              "\"ca\":\"fake-ca\"" +
            "}" +
          "}";
        BaseSecretSetRequest deserialize = deserialize(json, BaseSecretSetRequest.class);

        assertThat(deserialize, instanceOf(CertificateSetRequest.class));

      });
    });

    describe("when no value is set", () -> {
      it("should be in invalid", () -> {
        String json = "{\n" +
          "  \"name\": \"/example/certificate\",\n" +
          "  \"type\": \"certificate\"\n" +
          "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(json, BaseSecretSetRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when value is an empty object", () -> {
      it("should be invalid", () -> {
        String json = "{\n" +
          "  \"name\": \"/example/certificate\",\n" +
          "  \"type\": \"certificate\",\n" +
          "  \"value\": {}\n" +
          "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(json, BaseSecretSetRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_certificate_credentials")));
      });
    });

    describe("when certificate has all null sub-fields", () -> {
      it("should be invalid", () -> {
        String json = "{\n" +
          "  \"name\": \"/example/certificate\",\n" +
          "  \"type\": \"certificate\",\n" +
          "  \"value\": {" +
          "    \"ca\": \"\"," +
          "    \"certificate\": \"\"," +
          "    \"private_key\": \"\"" +
          "  }" +
          "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(json, BaseSecretSetRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_certificate_credentials")));
      });
    });
  }
}
