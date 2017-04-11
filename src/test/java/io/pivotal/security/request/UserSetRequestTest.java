package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class UserSetRequestTest {

  private String validSetRequestJson;

  {
    beforeEach(() -> {
      // language=JSON
      validSetRequestJson = "{\n" +
          "  \"name\": \"some-name\",\n" +
          "  \"type\": \"user\",\n" +
          "  \"overwrite\": true,\n" +
          "  \"value\": {\n" +
          "    \"username\": \"dan\",\n" +
          "    \"password\": \"example-password\"\n" +
          "  }\n" +
          "}";
    });

    describe("when value is empty", () -> {
      it("should be invalid", () -> {
        // language=JSON
        String json = "{\n" +
            "  \"name\": \"some-name\",\n" +
            "  \"type\": \"user\",\n" +
            "  \"overwrite\": true\n" +
            "}";
        UserSetRequest userSetRequest = (UserSetRequest) deserialize(json,
            BaseSecretSetRequest.class);
        Set<ConstraintViolation<UserSetRequest>> violations = validate(userSetRequest);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when all fields are set", () -> {
      it("should be valid", () -> {
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(validSetRequestJson,
            BaseSecretSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should have valid 'value' field", () -> {
        UserSetRequest userSetRequest = JsonHelper.deserialize(validSetRequestJson, UserSetRequest.class);

        UserSetRequestFields fields = userSetRequest.getUserSetRequestFields();
        assertThat(fields.getUsername(), equalTo("dan"));
        assertThat(fields.getPassword(), equalTo("example-password"));
      });
    });
  }
}
