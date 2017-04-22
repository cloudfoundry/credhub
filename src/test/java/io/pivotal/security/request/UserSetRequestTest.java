package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.credential.User;
import io.pivotal.security.helper.JsonHelper;
import org.junit.Assert;
import org.junit.runner.RunWith;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.JsonHelper.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.instanceOf;
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

    it("deserializes to UserSetRequest", () -> {
      BaseCredentialSetRequest userSetRequest = JsonHelper.deserializeChecked(validSetRequestJson, BaseCredentialSetRequest.class);

      Assert.assertThat(userSetRequest, instanceOf(UserSetRequest.class));
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
            BaseCredentialSetRequest.class);
        Set<ConstraintViolation<UserSetRequest>> violations = validate(userSetRequest);

        assertThat(violations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });

    describe("when all fields are set", () -> {
      it("should be valid", () -> {
        Set<ConstraintViolation<BaseCredentialSetRequest>> violations = deserializeAndValidate(validSetRequestJson,
            BaseCredentialSetRequest.class);

        assertThat(violations.size(), equalTo(0));
      });

      it("should have valid 'value' field", () -> {
        UserSetRequest userSetRequest = JsonHelper.deserialize(validSetRequestJson, UserSetRequest.class);

        User userValue = userSetRequest.getUserValue();
        assertThat(userValue.getUsername(), equalTo("dan"));
        assertThat(userValue.getPassword(), equalTo("example-password"));
      });
    });
  }
}
