package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import java.util.Set;
import javax.validation.ConstraintViolation;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class KeySetRequestFieldsTest {

  {
    it("should be invalid if no field is set", () -> {
      KeySetRequestFields keySetRequestFields = new KeySetRequestFields();
      Set<ConstraintViolation<KeySetRequestFields>> constraintViolations = validate(
          keySetRequestFields);

      assertThat(constraintViolations,
          contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
    });

    it("should be valid if only privateKey is set", () -> {
      KeySetRequestFields keySetRequestFields = new KeySetRequestFields();
      keySetRequestFields.setPrivateKey("la la land");
      Set<ConstraintViolation<KeySetRequestFields>> constraintViolations = validate(
          keySetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be valid if only publicKey is set", () -> {
      KeySetRequestFields keySetRequestFields = new KeySetRequestFields();
      keySetRequestFields.setPublicKey("la la land");
      Set<ConstraintViolation<KeySetRequestFields>> constraintViolations = validate(
          keySetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be valid if multiple fields are set", () -> {
      KeySetRequestFields keySetRequestFields = new KeySetRequestFields();
      keySetRequestFields.setPublicKey("la la land");
      keySetRequestFields.setPrivateKey("la la land");
      Set<ConstraintViolation<KeySetRequestFields>> constraintViolations = validate(
          keySetRequestFields);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    it("should be invalid if all fields are set to empty strings", () -> {
      KeySetRequestFields keySetRequestFields = new KeySetRequestFields();
      keySetRequestFields.setPublicKey("");
      keySetRequestFields.setPrivateKey("");
      Set<ConstraintViolation<KeySetRequestFields>> constraintViolations = validate(
          keySetRequestFields);

      assertThat(constraintViolations,
          contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
    });

    it("should be invalid if all fields are set to null", () -> {
      KeySetRequestFields keySetRequestFields = new KeySetRequestFields();
      keySetRequestFields.setPublicKey(null);
      keySetRequestFields.setPrivateKey(null);
      Set<ConstraintViolation<KeySetRequestFields>> constraintViolations = validate(
          keySetRequestFields);

      assertThat(constraintViolations,
          contains(hasViolationWithMessage("error.missing_rsa_ssh_parameters")));
    });
  }
}