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
public class CertificateSetRequestTest {

  {
    describe("when the value is valid", () -> {
      it("should not have violations", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"fake-certificate\","
            + "\"private_key\":\"fake-private-key\","
            + "\"ca\":\"fake-ca\""
            + "}"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should should deserialize to a CertificateSetRequest", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"fake-certificate\","
            + "\"private_key\":\"fake-private_key\","
            + "\"ca\":\"fake-ca\""
            + "}"
            + "}";
        BaseCredentialSetRequest deserialize = deserialize(json, BaseCredentialSetRequest.class);

        assertThat(deserialize, instanceOf(CertificateSetRequest.class));

      });

      it("should not require the certificate", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"private_key\":\"fake-private-key\","
            + "\"ca\":\"fake-ca\""
            + "}"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should set an empty certificate to null", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"\","
            + "\"private_key\":\"fake-private-key\","
            + "\"ca\":\"fake-ca\""
            + "}"
            + "}";
        CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);

        assertNull(certificateSetRequest.getCertificateValue().getCertificate());
      });

      it("should not require the private key", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"fake-certificate\","
            + "\"ca\":\"fake-ca\""
            + "}"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should set an empty certificate to null", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"fake-certificate\","
            + "\"private_key\":\"\","
            + "\"ca\":\"fake-ca\""
            + "}"
            + "}";
        CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);

        assertNull(certificateSetRequest.getCertificateValue().getPrivateKey());
      });

      it("should not require the CA", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"fake-certificate\","
            + "\"private_key\":\"fake-private-key\""
            + "}"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should set an empty CA to null", () -> {
        String json = "{"
            + "\"name\": \"/example/certificate\","
            + "\"type\": \"certificate\","
            + "\"value\": {"
            + "\"certificate\":\"fake-certificate\","
            + "\"private_key\":\"fake-private-key\","
            + "\"ca\":\"\""
            + "}"
            + "}";
        CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);

        assertNull(certificateSetRequest.getCertificateValue().getCa());
      });
    });

    describe("when no value is set", () -> {
      it("should be in invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\"\n"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when value is an empty object", () -> {
      it("should be invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": {}\n"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations,
            contains(hasViolationWithMessage("error.missing_certificate_credentials")));
      });
    });

    describe("when certificate has all empty string sub-fields", () -> {
      it("should be invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": {"
            + "    \"ca\": \"\","
            + "    \"certificate\": \"\","
            + "    \"private_key\": \"\""
            + "  }"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations,
            contains(hasViolationWithMessage("error.missing_certificate_credentials")));
      });
    });

    describe("when certificate has all null string sub-fields", () -> {
      it("should be invalid", () -> {
        String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": {"
            + "    \"ca\": null,"
            + "    \"certificate\": null,"
            + "    \"private_key\": null"
            + "  }"
            + "}";
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
            BaseCredentialSetRequest.class);

        assertThat(violations,
            contains(hasViolationWithMessage("error.missing_certificate_credentials")));
      });
    });
  }
}
