package io.pivotal.security.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
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
public class SecretSetRequestTest {

  private Validator validator;

  {
    beforeEach(() -> {
      final ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
      validator = validatorFactory.getValidator();
    });

    describe("when given valid json", () -> {
      it("should be valid", () -> {
        String json = "{" +
            "\"type\":\"some-type\"," +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"" +
            "}";
        SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);
        Set<ConstraintViolation<SecretSetRequest>> violations = validator.validate(secretSetRequest);
        
        assertThat(violations.size(), equalTo(0));
      });

      it("should set the correct fields", () -> {
        String json = "{" +
            "\"type\":\"some-type\"," +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"" +
          "}";
        SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

        assertThat(secretSetRequest.getType(), equalTo("some-type"));
        assertThat(secretSetRequest.getName(), equalTo("some-name"));
        assertThat(secretSetRequest.getValue(), equalTo("some-value"));
      });

      describe("#isOverwrite", () -> {
        it("should default to false", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"" +
            "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(false));
        });

        it("should take the provide value if set", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
            "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(true));
        });
      });
    });

    describe("validation", () -> {
      describe("when name is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"some-type\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          Set<ConstraintViolation<SecretSetRequest>> violations = validator.validate(secretSetRequest);
          assertThat(violations.size(), equalTo(1));
          String invalidField = violations.iterator().next().getPropertyPath().toString();
          assertThat(invalidField, equalTo("name"));
        });
      });

      describe("when name is an empty string", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"\"," +
              "\"type\":\"some-type\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          Set<ConstraintViolation<SecretSetRequest>> violations = validator.validate(secretSetRequest);
          assertThat(violations.size(), equalTo(1));
          String invalidField = violations.iterator().next().getPropertyPath().toString();
          assertThat(invalidField, equalTo("name"));
        });
      });

      describe("when type is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          Set<ConstraintViolation<SecretSetRequest>> violations = validator.validate(secretSetRequest);
          assertThat(violations.size(), equalTo(1));
          String invalidField = violations.iterator().next().getPropertyPath().toString();
          assertThat(invalidField, equalTo("type"));
        });
      });

      describe("when type is an empty string", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"type\":\"\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          Set<ConstraintViolation<SecretSetRequest>> violations = validator.validate(secretSetRequest);
          assertThat(violations.size(), equalTo(1));
          String invalidField = violations.iterator().next().getPropertyPath().toString();
          assertThat(invalidField, equalTo("type"));
        });
      });

      describe("when value is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"type\":\"some-type\"," +
              "\"overwrite\":true" +
              "}";
          SecretSetRequest secretSetRequest = new ObjectMapper().readValue(json, SecretSetRequest.class);

          Set<ConstraintViolation<SecretSetRequest>> violations = validator.validate(secretSetRequest);
          assertThat(violations.size(), equalTo(1));
          String invalidField = violations.iterator().next().getPropertyPath().toString();
          assertThat(invalidField, equalTo("value"));
        });
      });
    });
  }
}
