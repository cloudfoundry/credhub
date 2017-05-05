package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.credential.JsonCredentialValue;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.validation.ConstraintViolation;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class JsonSetRequestTest {

  {
    it("should deserialize to JsonSetRequest", () -> {
      String requestJson = "{\"name\":\"/my-namespace/subTree/credential-name\","
          + "\"type\":\"json\","
          + "\"value\":{\"key\":\"value\",\"fancy\":{\"num\":10},\"array\":[\"foo\",\"bar\"]},"
          + "\"overwrite\":false,"
          + "\"access_control_entries\": [{\"actor\": \"app1-guid\",\"operations\": [\"read\"]}]}";

      BaseCredentialSetRequest deserialize = deserialize(requestJson,
          BaseCredentialSetRequest.class);

      assertThat(deserialize, instanceOf(JsonSetRequest.class));
    });

    it("should be valid if all fields are set", () -> {
      Map<String, Object> nested = new HashMap<>();
      nested.put("key", 3);

      Map<String, Object> value = new HashMap<>();
      value.put("foo", "bar");
      value.put("nested", nested);

      JsonSetRequest request = new JsonSetRequest();
      request.setName("some-name");
      request.setType("json");
      request.setValue(new JsonCredentialValue(value));
      request.setOverwrite(true);

      Set<ConstraintViolation<BaseCredentialSetRequest>> constraintViolations = validate(request);

      assertThat(constraintViolations.size(), equalTo(0));
    });

    describe("when value is not set", () -> {
      it("should be invalid", () -> {
        JsonSetRequest request = new JsonSetRequest();
        request.setName("some-name");
        request.setType("json");
        request.setOverwrite(true);

        Set<ConstraintViolation<BaseCredentialSetRequest>> constraintViolations = validate(request);

        assertThat(constraintViolations, contains(hasViolationWithMessage("error.missing_value")));
      });
    });
  }
}
