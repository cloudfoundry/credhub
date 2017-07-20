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
import static org.junit.Assert.assertNull;

@RunWith(Spectrum.class)
public class RsaSetRequestTest {

  {
    describe("when the value is valid", () -> {
      it("should not have violations", () -> {
        String json = "{"
            + "\"name\": \"/example/rsa\","
            + "\"type\": \"rsa\","
            + "\"value\": {"
            + "\"public_key\":\"fake-public-key\","
            + "\"private_key\":\"fake-private-key\""
            + "}"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      describe("when type has unusual casing", () -> {
            it("should be valid", () -> {
              String json = "{"
                  + "\"name\": \"/example/rsa\","
                  + "\"type\": \"RsA\","
                  + "\"value\": {"
                  + "\"public_key\":\"fake-public-key\","
                  + "\"private_key\":\"fake-private-key\""
                  + "}"
                  + "}";
              Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
                  RsaSetRequest.class);

              assertThat(violations.size(), equalTo(0));
            });
      });

      it("should should deserialize to a RsaSetRequest", () -> {
        String json = "{"
            + "\"name\": \"/example/rsa\","
            + "\"type\": \"rsa\","
            + "\"value\": {"
            + "\"public_key\":\"fake-public-key\","
            + "\"private_key\":\"fake-private-key\""
            + "}"
            + "}";
        RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

        assertThat(deserialize, instanceOf(RsaSetRequest.class));
      });

      it("should not require the public key RsaSetRequest", () -> {
        String json = "{"
            + "\"name\": \"/example/rsa\","
            + "\"type\": \"rsa\","
            + "\"value\": {"
            + "\"private_key\":\"fake-private-key\""
            + "}"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should not require the private key RsaSetRequest", () -> {
        String json = "{"
            + "\"name\": \"/example/rsa\","
            + "\"type\": \"rsa\","
            + "\"value\": {"
            + "\"public_key\":\"fake-public-key\""
            + "}"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should coerce an empty public key into null", () -> {
        String json = "{"
            + "\"name\": \"/example/rsa\","
            + "\"type\": \"rsa\","
            + "\"value\": {"
            + "\"public_key\":\"\","
            + "\"private_key\":\"fake-private-key\""
            + "}"
            + "}";
        RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

        assertNull(deserialize.getRsaKeyValue().getPublicKey());
      });

      it("should coerce an empty private key into null", () -> {
        String json = "{"
            + "\"name\": \"/example/rsa\","
            + "\"type\": \"rsa\","
            + "\"value\": {"
            + "\"public_key\":\"fake-public-key\","
            + "\"private_key\":\"\""
            + "}"
            + "}";
        RsaSetRequest deserialize = deserialize(json, RsaSetRequest.class);

        assertNull(deserialize.getRsaKeyValue().getPrivateKey());
      });
    });

    describe("when no value is set", () -> {
      it("should be in invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/rsa\",\n"
            + "  \"type\": \"rsa\"\n"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when value is an empty object", () -> {
      it("should be invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/rsa\",\n"
            + "  \"type\": \"rsa\",\n"
            + "  \"value\": {}\n"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations,
            contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
      });
    });

    describe("when rsa has all empty string sub-fields", () -> {
      it("should be invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/rsa\",\n"
            + "  \"type\": \"rsa\",\n"
            + "  \"value\": {"
            + "    \"public_key\":\"\","
            + "    \"private_key\":\"\""
            + "  }"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations,
            contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
      });
    });

    describe("when rsa has all null string sub-fields", () -> {
      it("should be invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/rsa\",\n"
            + "  \"type\": \"rsa\",\n"
            + "  \"value\": {"
            + "    \"public_key\":null,"
            + "    \"private_key\":null"
            + "  }"
            + "}";
        Set<ConstraintViolation<RsaSetRequest>> violations = deserializeAndValidate(json,
            RsaSetRequest.class);

        assertThat(violations,
            contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
      });
    });
  }
}
