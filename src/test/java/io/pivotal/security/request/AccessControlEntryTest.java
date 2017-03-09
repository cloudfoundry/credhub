package io.pivotal.security.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

import java.util.Set;

import javax.validation.ConstraintViolation;

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
          Set<ConstraintViolation<AccessControlEntry>> constraintViolations = deserializeAndValidate(json, AccessControlEntry.class);
          assertThat(constraintViolations, contains(hasViolationWithMessage("error.acl.missing_actor")));
        });

        it("should validate non-emptiness of actor", () -> {
          String json = "{ \n" +
              "\"actor\":\"\"," +
              "\"operations\": [\"read\"]\n" +
              "}";
          Set<ConstraintViolation<AccessControlEntry>> constraintViolations = deserializeAndValidate(json, AccessControlEntry.class);
          assertThat(constraintViolations, contains(hasViolationWithMessage("error.acl.missing_actor")));
        });

        describe("on operations", () -> {
          it("should disallow null", () -> {
            String json = "{" +
                "\"actor\": \"dan\"" +
              "}";
            Set<ConstraintViolation<AccessControlEntry>> constraintViolations = deserializeAndValidate(json, AccessControlEntry.class);
            assertThat(constraintViolations, contains(hasViolationWithMessage("error.acl.missing_operations")));
          });

          it("should disallow empty list", () -> {
            String json = "{" +
                "\"actor\": \"dan\"," +
                "\"operations\": []" +
              "}";
            Set<ConstraintViolation<AccessControlEntry>> constraintViolations = deserializeAndValidate(json, AccessControlEntry.class);
            assertThat(constraintViolations, contains(hasViolationWithMessage("error.acl.missing_operations")));
          });

          itThrows("should not allow invalid operations", InvalidFormatException.class, () -> {
            String json = "{ \n" +
                "\"actor\": \"dan\",\n" +
                "\"operations\": [\"foo\", \"read\"]\n" +
                "}";
            try {
              deserializeAndValidate(json, AccessControlEntry.class);
            } catch (RuntimeException e) {
              throw e.getCause();
            }
          });
        });
      });
    });
  }
}
