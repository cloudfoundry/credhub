package io.pivotal.security.request;

import com.google.common.collect.ImmutableMap;
import io.pivotal.security.helper.TestHelper;
import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static io.pivotal.security.util.TestConstants.TEST_CA;
import static io.pivotal.security.util.TestConstants.TEST_CERTIFICATE;
import static io.pivotal.security.util.TestConstants.TEST_PRIVATE_KEY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNull;

@RunWith(JUnit4.class)
public class CertificateSetRequestTest {

  final String setJson = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("ca_name", "CA_NAME")
          .put("certificate", TEST_CERTIFICATE)
          .put("private_key", TEST_PRIVATE_KEY)
          .build());

  @Before
  public void beforeEach() {
    TestHelper.getBouncyCastleProvider();
  }

  @Test
  public void whenTheValueIsValid_hasNoViolations() {
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\":" + setJson
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTheTypeHasUnusualCasing_hasNoViolations() {
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"CeRtIfIcAtE\","
        + "\"value\": " + setJson
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenTheValueIsValid_deserializesToACertificateSetRequest() {
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\": " + setJson
        + "}";
    CertificateSetRequest deserialize = deserialize(json, CertificateSetRequest.class);

    assertThat(deserialize, instanceOf(CertificateSetRequest.class));
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireTheCertificate() {
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\": {"
        + "\"private_key\":\"fake-private-key\","
        + "\"ca\":\"fake-ca\""
        + "}"
        + "}";

    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getCertificate());
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireThePrivateKey() {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "CA_NAME")
            .put("certificate", TEST_CERTIFICATE)
            .build());

    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\": " + setJson
        + "}";

    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getPrivateKey());
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireTheCA() {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .build());
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\": " + setJson
        + "}";

    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getCa());
  }

  @Test
  public void whenTheCaNameIsNotEmpty_setsTheCaName() {
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\": {"
        + "\"certificate\":\"test-certificate\","
        + "\"private_key\":\"fake-private-key\","
        + "\"ca_name\":\"test-ca-name\""
        + "}"
        + "}";

    CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertThat(certificateSetRequest.getCertificateValue().getCaName(), equalTo("/test-ca-name"));
  }

  @Test
  public void whenNoValueIsSet_isInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\"\n"
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void whenValueIsAnEmptyObject_isInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": {}\n"
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_certificate_credentials")));
  }

  @Test
  public void whenValueHasAllEmptyStringSubFields_isInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": {"
        + "    \"ca\": \"\","
        + "    \"ca_name\": \"\","
        + "    \"certificate\": \"\","
        + "    \"private_key\": \"\""
        + "  }"
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_certificate_credentials")));
  }

  @Test
  public void whenValueHasAllNullStringSubFields_isInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": {"
        + "    \"ca\": null,"
        + "    \"ca_name\": null,"
        + "    \"certificate\": null,"
        + "    \"private_key\": null"
        + "  }"
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(json,
        CertificateSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_certificate_credentials")));
  }

  @Test
  public void whenValueHasBothCaAndCaName_isInvalid() {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "CA_NAME")
            .put("certificate", TEST_CERTIFICATE)
            .put("private_key", TEST_PRIVATE_KEY)
            .put("ca", TEST_CA)
            .build());
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": " + setJson
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
        json,
        CertificateSetRequest.class
    );

    assertThat(violations, contains(hasViolationWithMessage("error.mixed_ca_name_and_ca")));
  }

  @Test
  public void whenCertificateValueIsNotValidX509Certificate_isInvalid() {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "CA_NAME")
            .put("certificate", "invalid x509 certificate")
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": " + setJson
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
        json,
        CertificateSetRequest.class
    );

    assertThat(violations, contains(hasViolationWithMessage("error.invalid_certificate_value")));
  }

  @Test
  public void whenCertificateValueIsValidX509CertificateButHasTrailingText_isValid() {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "CA_NAME")
            .put("certificate", TEST_CERTIFICATE+"this is a comment at the end of a valid cert")
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": " + setJson
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
        json,
        CertificateSetRequest.class
    );

    assertThat(violations.size(), equalTo(0));
  }

  @Test
  public void whenCertificateValueIsLongerThan7000Chars_isInvalid() {
    int repetitionCount = 7001 - TEST_CERTIFICATE.length();
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "CA_NAME")
            .put("certificate", TEST_CERTIFICATE + StringUtils.repeat("a", repetitionCount))
            .put("private_key", TEST_PRIVATE_KEY)
            .build());

    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": " + setJson
        + "}";
    Set<ConstraintViolation<CertificateSetRequest>> violations = deserializeAndValidate(
        json,
        CertificateSetRequest.class
    );

    assertThat(violations, contains(hasViolationWithMessage("error.invalid_certificate_length")));
  }
}
