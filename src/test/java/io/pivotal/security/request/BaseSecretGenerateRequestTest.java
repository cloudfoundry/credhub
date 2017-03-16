package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;

@RunWith(Spectrum.class)
public class BaseSecretGenerateRequestTest {
  {
    describe("#validate", () -> {
      describe("when type is not set", () -> {
        itThrowsWithMessage("should throw type_invalid error",
            ParameterizedValidationException.class,
            "error.type_invalid",
            () -> {
              String json = "{" +
                  "\"name\":\"some-name\"," +
                  "\"overwrite\":true" +
                  "}";

              BaseSecretGenerateRequest request = JsonHelper.deserialize(json, BaseSecretGenerateRequest.class);
              request.validate();
            });
      });

      describe("when type is an empty string", () -> {
        itThrowsWithMessage("should throw type_invalid error",
            ParameterizedValidationException.class,
            "error.type_invalid",
            () -> {
              String json = "{" +
                  "\"name\":\"some-name\"," +
                  "\"type\":\"\"," +
                  "\"overwrite\":true" +
                  "}";

              BaseSecretGenerateRequest request = JsonHelper.deserialize(json, BaseSecretGenerateRequest.class);
              request.validate();
            });
      });

      describe("when type is not a generatable type", () -> {
        itThrowsWithMessage("should throw invalid_generate_type error",
            ParameterizedValidationException.class,
            "error.invalid_generate_type",
            () -> {
              String json = "{" +
                  "\"name\":\"some-name\"," +
                  "\"type\":\"json\"," +
                  "\"overwrite\":true" +
                  "}";

              BaseSecretGenerateRequest request = JsonHelper.deserialize(json, BaseSecretGenerateRequest.class);
              request.validate();
            });
      });
    });
  }
}
