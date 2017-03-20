package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class PasswordGenerateRequestTest {
  {
    describe("when deserializing and validating", () -> {
      describe("when all charsets are excluded", () -> {

        itThrowsWithMessage("should validate charsets",
            ParameterizedValidationException.class,
            "error.excludes_all_charsets",
            () -> {
              // language=JSON
              String badJsonExcludingAllCharsets = "{\n" +
                  "  \"name\": \"APasswordRequest\",\n" +
                  "  \"regenerate\": false,\n" +
                  "  \"type\": \"password\",\n" +
                  "  \"overwrite\": true,\n" +
                  "  \"parameters\": {\n" +
                  "    \"exclude_lower\": true,\n" +
                  "    \"exclude_upper\": true,\n" +
                  "    \"include_special\": false,\n" +
                  "    \"exclude_number\": true,\n" +
                  "    \"only_hex\": false\n" +
                  "  }\n" +
                  "}";

              PasswordGenerateRequest passwordGenerationRequest =
                  (PasswordGenerateRequest) JsonHelper.deserialize(
                      badJsonExcludingAllCharsets,
                      BaseSecretGenerateRequest.class);
              passwordGenerationRequest.validate();
            });
      });

      describe("when password parameters are omitted", () -> {
        it("it uses default parameters", () -> {
          // language=JSON
          String badJsonExcludingAllCharsets = "{\n" +
              "  \"name\": \"/APasswordRequest\",\n" +
              "  \"type\": \"password\"\n" +
              "}";

          PasswordGenerateRequest passwordGenerationRequest =
              (PasswordGenerateRequest) JsonHelper.deserialize(
                  badJsonExcludingAllCharsets,
                  BaseSecretGenerateRequest.class);
          passwordGenerationRequest.validate();

          PasswordGenerationParameters defaultParameters = passwordGenerationRequest.getGenerationParameters();
          assertThat(defaultParameters.getLength(), equalTo(PassayStringSecretGenerator.DEFAULT_LENGTH));
          assertThat(defaultParameters.isExcludeLower(), equalTo(false));
          assertThat(defaultParameters.isExcludeUpper(), equalTo(false));
          assertThat(defaultParameters.isExcludeNumber(), equalTo(false));
          assertThat(defaultParameters.isOnlyHex(), equalTo(false));
          assertThat(defaultParameters.isIncludeSpecial(), equalTo(false));
        });
      });
    });
  }
}
