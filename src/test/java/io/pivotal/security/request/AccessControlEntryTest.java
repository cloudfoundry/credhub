package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.greghaskins.spectrum.Spectrum;
import java.util.Set;
import javax.validation.ConstraintViolation;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class AccessControlEntryTest {

  {
    describe("JSON serialization", () -> {
      describe("validation", () -> {
        it("should allow good JSON", () -> {
          String json = "{ \n"
              + "\"actor\": \"dan\",\n"
              + "\"operations\": [\"read\"]\n"
              + "}";
          ObjectMapper om = new ObjectMapper();
          PermissionEntry permissionEntry = om.readValue(json, PermissionEntry.class);
          assertThat(permissionEntry.getActor(), equalTo("dan"));
        });

        it("should validate presence of actor", () -> {
          String json = "{ \n"
              + "\"operations\": [\"read\"]\n"
              + "}";
          Set<ConstraintViolation<PermissionEntry>> constraintViolations =
              deserializeAndValidate(json, PermissionEntry.class);
          assertThat(constraintViolations,
              contains(hasViolationWithMessage("error.acl.missing_actor")));
        });

        it("should validate non-emptiness of actor", () -> {
          String json = "{ \n"
              + "\"actor\":\"\","
              + "\"operations\": [\"read\"]\n"
              + "}";
          Set<ConstraintViolation<PermissionEntry>> constraintViolations =
              deserializeAndValidate(json, PermissionEntry.class);
          assertThat(constraintViolations,
              contains(hasViolationWithMessage("error.acl.missing_actor")));
        });

        describe("on operations", () -> {
          it("should disallow null", () -> {
            String json = "{"
                + "\"actor\": \"dan\""
                + "}";
            Set<ConstraintViolation<PermissionEntry>> constraintViolations =
                deserializeAndValidate(json, PermissionEntry.class);
            assertThat(constraintViolations,
                contains(hasViolationWithMessage("error.acl.missing_operations")));
          });

          it("should disallow empty list", () -> {
            String json = "{"
                + "\"actor\": \"dan\","
                + "\"operations\": []"
                + "}";
            Set<ConstraintViolation<PermissionEntry>> constraintViolations =
                deserializeAndValidate(json, PermissionEntry.class);
            assertThat(constraintViolations,
                contains(hasViolationWithMessage("error.acl.missing_operations")));
          });

          itThrows("should not allow invalid operations", InvalidFormatException.class, () -> {
            String json = "{ \n"
                + "\"actor\": \"dan\",\n"
                + "\"operations\": [\"foo\", \"read\"]\n"
                + "}";
            try {
              deserializeAndValidate(json, PermissionEntry.class);
            } catch (RuntimeException e) {
              throw e.getCause();
            }
          });
        });
      });
    });
  }
}
