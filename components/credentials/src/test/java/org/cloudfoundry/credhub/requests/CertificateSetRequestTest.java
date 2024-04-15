package org.cloudfoundry.credhub.requests;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.ValidationException;

import com.google.common.collect.ImmutableMap;
import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.TestHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserialize;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.utils.TestConstants.OTHER_TEST_CERTIFICATE;
import static org.cloudfoundry.credhub.utils.TestConstants.PRIVATE_KEY_4096;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_CA;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_CERTIFICATE;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_PRIVATE_KEY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

public class CertificateSetRequestTest {

  final String setJson = JSONObject.toJSONString(
    ImmutableMap.<String, String>builder()
      .put("ca_name", "CA_NAME")
      .put("certificate", TEST_CERTIFICATE)
      .put("private_key", TEST_PRIVATE_KEY)
      .build());

  @BeforeEach
  public void beforeEach() {
    TestHelper.getBouncyCastleFipsProvider();
  }

  @Test
  public void whenTheValueIsValid_hasNoViolations() {
    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"certificate\","
      + "\"value\":" + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTheTypeHasUnusualCasing_hasNoViolations() {
    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"CeRtIfIcAtE\","
      + "\"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTheValueIsValid_deserializesToACertificateSetRequest() {
    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"certificate\","
      + "\"value\": " + setJson
      + "}";
    final CertificateSetRequest deserialize = deserialize(json, CertificateSetRequest.class);

    assertThat(deserialize, instanceOf(CertificateSetRequest.class));
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireTheCertificate() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca", TEST_CA)
        .put("private_key", TEST_PRIVATE_KEY)
        .build());

    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"certificate\","
      + "\"value\": " + setJson
      + "}";

    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    final CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getCertificate());
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireThePrivateKey() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "CA_NAME")
        .put("certificate", TEST_CERTIFICATE)
        .build());

    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"certificate\","
      + "\"value\": " + setJson
      + "}";

    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    final CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getPrivateKey());
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireTheCA() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("certificate", TEST_CERTIFICATE)
        .put("private_key", TEST_PRIVATE_KEY)
        .build());
    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"certificate\","
      + "\"value\": " + setJson
      + "}";

    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    final CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getCa());
  }

  @Test
  public void whenTheCaNameIsNotEmpty_setsTheCaName() {
    final String json = "{"
      + "\"name\": \"/example/certificate\","
      + "\"type\": \"certificate\","
      + "\"value\": {"
      + "\"certificate\":\"test-certificate\","
      + "\"private_key\":\"fake-private-key\","
      + "\"ca_name\":\"test-ca-name\""
      + "}"
      + "}";

    final CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertThat(certificateSetRequest.getCertificateValue().getCaName(), equalTo("/test-ca-name"));
  }

  @Test
  public void whenNoValueIsSet_isInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\"\n"
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.MISSING_VALUE)));
  }

  @Test
  public void whenValueIsAnEmptyObject_isInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": {}\n"
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);

    assertThat(violations,
      hasItem(hasViolationWithMessage(ErrorMessages.MISSING_CERTIFICATE_CREDENTIALS)));
  }

  @Test
  public void whenValueHasAllEmptyStringSubFields_isInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": {"
      + "    \"ca\": \"\","
      + "    \"ca_name\": \"\","
      + "    \"certificate\": \"\","
      + "    \"private_key\": \"\""
      + "  }"
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);

    assertThat(violations,
      hasItem(hasViolationWithMessage(ErrorMessages.MISSING_CERTIFICATE_CREDENTIALS)));
  }

  @Test
  public void whenValueHasAllNullStringSubFields_isInvalid() {
    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": {"
      + "    \"ca\": null,"
      + "    \"ca_name\": null,"
      + "    \"certificate\": null,"
      + "    \"private_key\": null"
      + "  }"
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
      CertificateSetRequest.class);

    assertThat(violations,
      hasItem(hasViolationWithMessage(ErrorMessages.MISSING_CERTIFICATE_CREDENTIALS)));
  }

  @Test
  public void whenValueHasBothCaAndCaName_isInvalid() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "CA_NAME")
        .put("certificate", TEST_CERTIFICATE)
        .put("private_key", TEST_PRIVATE_KEY)
        .put("ca", TEST_CA)
        .build()
    );
    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.MIXED_CA_NAME_AND_CA)));
  }

  @Test
  public void whenCertificateValueIsNotValidX509Certificate_isInvalid() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "CA_NAME")
        .put("certificate", "invalid x509 certificate")
        .put("private_key", TEST_PRIVATE_KEY)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";

    assertThatThrownBy(() -> {
      deserializeAndValidate(
        json,
        CertificateSetRequest.class
      );
    }).isInstanceOf(ValidationException.class);
  }

  @Test
  public void whenCertificateValueIsValidX509CertificateButHasTrailingText_isValid() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "CA_NAME")
        .put("certificate", TEST_CERTIFICATE + "this is a comment at the end of a valid cert")
        .put("private_key", TEST_PRIVATE_KEY)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenCertificateValueIsLongerThan7000Chars_isInvalid() {
    final int repetitionCount = 7001 - TEST_CERTIFICATE.length();
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "CA_NAME")
        .put("certificate", TEST_CERTIFICATE + StringUtils.repeat("a", repetitionCount))
        .put("private_key", TEST_PRIVATE_KEY)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.INVALID_CERTIFICATE_LENGTH)));
  }

  @Test
  public void whenCAValueIsLongerThan7000Chars_isInvalid() {
    final int repetitionCount = 7001 - TEST_CA.length();
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca", TEST_CA + StringUtils.repeat("a", repetitionCount))
        .put("certificate", TEST_CERTIFICATE)
        .put("private_key", TEST_PRIVATE_KEY)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.INVALID_CERTIFICATE_LENGTH)));
  }

  @Test
  public void whenCAValueIsInvalidX509Certificate_isInvalid() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca", "CA")
        .put("certificate", TEST_CERTIFICATE)
        .put("private_key", TEST_PRIVATE_KEY)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.INVALID_CA_VALUE)));
  }

  @Test
  public void whenCertificateWasNoSignedByTheCA_isInvalid() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca", TEST_CERTIFICATE)
        .put("certificate", TEST_CERTIFICATE)
        .put("private_key", TEST_PRIVATE_KEY)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.CERTIFICATE_WAS_NOT_SIGNED_BY_CA)));
  }

  @Test
  public void whenCAValueIsNotACertificateAuthorityAndDifferentThanCertificate_isInvalid() {
    final String setJson = JSONObject.toJSONString(
            ImmutableMap.<String, String>builder()
                    .put("ca", OTHER_TEST_CERTIFICATE)
                    .put("certificate", TEST_CERTIFICATE)
                    .put("private_key", TEST_PRIVATE_KEY)
                    .build()
    );

    final String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": " + setJson
            + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
            json,
            CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.INVALID_CA_VALUE)));
  }

  @Test
  public void whenNoCaCertificateWasProvided_isValid() {
    final String setJson = JSONObject.toJSONString(
            ImmutableMap.<String, String>builder()
                    .put("certificate", TEST_CERTIFICATE)
                    .put("private_key", TEST_PRIVATE_KEY)
                    .build()
    );

    final String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": " + setJson
            + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
            json,
            CertificateSetRequest.class
    );

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenNoCaAndNoCertificateWasProvided_isValid() {
    final String setJson = JSONObject.toJSONString(
            ImmutableMap.<String, String>builder()
                    .put("private_key", TEST_PRIVATE_KEY)
                    .build()
    );

    final String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": " + setJson
            + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
            json,
            CertificateSetRequest.class
    );

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenCertificateDoesNotMatchPrivateKey_isInvalid() {
    final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
        .put("ca", TEST_CA)
        .put("certificate", TEST_CERTIFICATE)
        .put("private_key", PRIVATE_KEY_4096)
        .build()
    );

    final String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": " + setJson
      + "}";
    final Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
      json,
      CertificateSetRequest.class
    );

    assertThat(violations, hasItem(hasViolationWithMessage(ErrorMessages.MISMATCHED_CERTIFICATE_AND_PRIVATE_KEY)));
  }
}
