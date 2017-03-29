package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;

import com.greghaskins.spectrum.Spectrum;
import java.util.Set;
import javax.validation.ConstraintViolation;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class CertificateSetRequestFieldsTest {

  {
    it("should be invalid if no field is set", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations,
          contains(hasViolationWithMessage("error.missing_certificate_credentials")));
    });

    it("should be valid if only certificate is set", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      certificateSetRequestFields.setCertificate("la la land");
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be valid if only ca is set", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      certificateSetRequestFields.setCa("la la land");
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be valid if only privateKey is set", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      certificateSetRequestFields.setPrivateKey("la la land");
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be valid if multiple fields are set", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      certificateSetRequestFields.setCertificate("la la land");
      certificateSetRequestFields.setPrivateKey("la la land");
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be invalid if all fields are set to empty strings", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      certificateSetRequestFields.setCertificate("");
      certificateSetRequestFields.setPrivateKey("");
      certificateSetRequestFields.setCa("");
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations,
          contains(hasViolationWithMessage("error.missing_certificate_credentials")));
    });

    it("should be invalid if all fields are set to null", () -> {
      CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields();
      certificateSetRequestFields.setCertificate(null);
      certificateSetRequestFields.setPrivateKey(null);
      certificateSetRequestFields.setCa(null);
      Set<ConstraintViolation<CertificateSetRequestFields>> constraintViolations = validate(
          certificateSetRequestFields);

      assertThat(constraintViolations,
          contains(hasViolationWithMessage("error.missing_certificate_credentials")));
    });
  }
}