package io.pivotal.security.request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNull;

@RunWith(JUnit4.class)
public class CertificateSetRequestTest {
  @Test
  public void whenTheValueIsValid_hasNoViolations() {
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
  }

  @Test
  public void whenTheValueIsValid_deserializesToACertificateSetRequest() {
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

    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getCertificate());
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireThePrivateKey() {
    String json = "{"
        + "\"name\": \"/example/certificate\","
        + "\"type\": \"certificate\","
        + "\"value\": {"
        + "\"certificate\":\"fake-certificate\","
        + "\"private_key\":\"\","
        + "\"ca\":\"fake-ca\""
        + "}"
        + "}";

    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);
    assertThat(violations.size(), equalTo(0));

    CertificateSetRequest certificateSetRequest = deserialize(json, CertificateSetRequest.class);
    assertNull(certificateSetRequest.getCertificateValue().getPrivateKey());
  }

  @Test
  public void whenTheValueIsValid_doesNotRequireTheCA() {
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
    assertThat(certificateSetRequest.getCertificateValue().getCaName(), equalTo("test-ca-name"));
  }

  @Test
  public void whenNoValueIsSet_isInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\"\n"
        + "}";
    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
  }

  @Test
  public void whenValueIsAnEmptyObject_isInvalid() {
    String json = "{\n"
        + "  \"name\": \"/example/certificate\",\n"
        + "  \"type\": \"certificate\",\n"
        + "  \"value\": {}\n"
        + "}";
    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);

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
    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);

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
    Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(json,
        BaseCredentialSetRequest.class);

    assertThat(violations,
        contains(hasViolationWithMessage("error.missing_certificate_credentials")));
  }
}
