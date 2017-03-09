package io.pivotal.security.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class PasswordSetRequestTest {

  private Validator validator;

  {
    beforeEach(() -> {
      final ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
      validator = validatorFactory.getValidator();
    });

    describe("when password is not set", () -> {
      it("should be invalid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"password\"," +
            "\"overwrite\":true" +
            "}";
        PasswordSetRequest passwordSetRequest = (PasswordSetRequest) new ObjectMapper().readValue(json, BaseSecretSetRequest.class);

        Set<ConstraintViolation<BaseSecretSetRequest>> violations = validator.validate(passwordSetRequest);
        assertThat(violations.size(), equalTo(1));
        String invalidField = violations.iterator().next().getPropertyPath().toString();
        assertThat(invalidField, equalTo("password"));
      });
    });

    describe("when password is empty", () -> {
      it("should be invalid", () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"password\"," +
            "\"overwrite\":true," +
            "\"value\":\"\"" +
            "}";
        PasswordSetRequest passwordSetRequest = (PasswordSetRequest) new ObjectMapper().readValue(json, BaseSecretSetRequest.class);

        Set<ConstraintViolation<BaseSecretSetRequest>> violations = validator.validate(passwordSetRequest);
        assertThat(violations.size(), equalTo(1));
        String invalidField = violations.iterator().next().getPropertyPath().toString();
        assertThat(invalidField, equalTo("password"));
      });
    });
  }
}
