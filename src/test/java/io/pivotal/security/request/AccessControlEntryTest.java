package io.pivotal.security.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.ValidatorFactory;
import javax.validation.groups.Default;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
public class AccessControlEntryTest {
  {
    describe("JSON serialization", () -> {
      describe("validation", () -> {
        it("should allow good JSON", () -> {
          String json = "{ \n" +
              "\"actor\": \"dan\",\n" +
              "\"operations\": [\"read\"]\n" +
              "}";
          ObjectMapper om = new ObjectMapper();
          AccessControlEntry accessControlEntry = om.readValue(json, AccessControlEntry.class);
          assertThat(accessControlEntry.getActor(), equalTo("dan"));
        });

        it("should validate presence of actor", () -> {
          String json = "{ \n" +
              "\"operations\": [\"read\"]\n" +
              "}";
          Set<ConstraintViolation<AccessControlEntry>> constraintViolations = serializeAndValidate(json, AccessControlEntry.class);
          assertThat(constraintViolations.size(), equalTo(1));
          assertThat(((ConstraintViolation) constraintViolations.toArray()[0]).getMessage(), equalTo("may not be null"));
        });

        describe("on operations", () -> {
          it("should validate allowed values", () -> {
            String json = "{ \n" +
                "\"actor\": \"dan\",\n" +
                "\"operations\": [\"foo\", \"read\"]\n" +
                "}";
            Set<ConstraintViolation<AccessControlEntry>> constraintViolations = serializeAndValidate(json, AccessControlEntry.class);
            assertThat(constraintViolations.size(), equalTo(1));
            assertThat(((ConstraintViolation) constraintViolations.toArray()[0]).getMessage(), equalTo("error.acl.invalid_operation"));
          });

          it("should validate on exact strings", () -> {
            String json = "{ \n" +
                "\"actor\": \"dan\",\n" +
                "\"operations\": [\"readership\"]\n" +
                "}";
            Set<ConstraintViolation<AccessControlEntry>> constraintViolations = serializeAndValidate(json, AccessControlEntry.class);
            assertThat(constraintViolations.size(), equalTo(1));
            assertThat(((ConstraintViolation) constraintViolations.toArray()[0]).getMessage(), equalTo("error.acl.invalid_operation"));
          });
        });
      });
    });
  }

  private <T> Set<ConstraintViolation<T>> serializeAndValidate(String json, Class<T> klass) throws java.io.IOException {
    T object = new ObjectMapper().readValue(json, klass);
    ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
    return validatorFactory.getValidator().validate(object, Default.class);
  }
}
