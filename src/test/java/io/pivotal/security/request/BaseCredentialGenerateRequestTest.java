package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;

@RunWith(Spectrum.class)
public class BaseCredentialGenerateRequestTest {

  {
    describe("#validate", () -> {
      describe("when the request is valid", () -> {
        it("should not have any constraint violations", () -> {
          String json = "{"
              + "\"name\":\"some-name\","
              + "\"type\":\"password\","
              + "\"overwrite\":true"
              + "}";

          BaseCredentialGenerateRequest request = JsonHelper
              .deserialize(json, BaseCredentialGenerateRequest.class);
          request.validate();

          // passes if we get here
        });
      });

      describe("#validate", () -> {
        describe("when type is not set", () -> {
          itThrowsWithMessage("should throw invalid_type_with_generate_prompt error",
              ParameterizedValidationException.class,
              "error.invalid_type_with_generate_prompt",
              () -> {
                String json = "{"
                    + "\"name\":\"some-name\","
                    + "\"overwrite\":true"
                    + "}";

                BaseCredentialGenerateRequest request = JsonHelper
                    .deserialize(json, BaseCredentialGenerateRequest.class);
                request.validate();
              });
        });

        describe("when type is an empty string", () -> {
          itThrowsWithMessage("should throw invalid_type_with_generate_prompt error",
              ParameterizedValidationException.class,
              "error.invalid_type_with_generate_prompt",
              () -> {
                String json = "{"
                    + "\"name\":\"some-name\","
                    + "\"type\":\"\","
                    + "\"overwrite\":true"
                    + "}";

                BaseCredentialGenerateRequest request = JsonHelper
                    .deserialize(json, BaseCredentialGenerateRequest.class);
                request.validate();
              });
        });
      });

      describe("when type is value", () -> {
        itThrowsWithMessage("should throw invalid_type_with_generate_prompt",
            ParameterizedValidationException.class,
            "error.cannot_generate_type",
            () -> {
              String json = "{"
                  + "\"name\":\"some-name\","
                  + "\"type\":\"value\","
                  + "\"overwrite\":true"
                  + "}";

              BaseCredentialGenerateRequest request = JsonHelper
                  .deserialize(json, BaseCredentialGenerateRequest.class);
              request.validate();
            });
      });

      describe("when type is json", () -> {
        itThrowsWithMessage("should throw invalid_type_with_generate_prompt",
            ParameterizedValidationException.class,
            "error.cannot_generate_type",
            () -> {
              String json = "{"
                  + "\"name\":\"some-name\","
                  + "\"type\":\"json\","
                  + "\"overwrite\":true"
                  + "}";

              BaseCredentialGenerateRequest request = JsonHelper
                  .deserialize(json, BaseCredentialGenerateRequest.class);
              request.validate();
            });
      });

      describe("when type is totally wrong", () -> {
        itThrowsWithMessage("should throw invalid_type_with_generate_prompt",
            ParameterizedValidationException.class,
            "error.invalid_type_with_generate_prompt",
            () -> {
              String json = "{"
                  + "\"name\":\"some-name\","
                  + "\"type\":\"banana\","
                  + "\"overwrite\":true"
                  + "}";

              BaseCredentialGenerateRequest request = JsonHelper
                  .deserialize(json, BaseCredentialGenerateRequest.class);
              request.validate();
            });
      });
    });
  }
}
