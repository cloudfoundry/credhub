package io.pivotal.security.mapper;


import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.generator.PasseyStringSecretGenerator;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.ParameterizedValidationException;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class PasswordGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @MockBean
  PasseyStringSecretGenerator secretGenerator;

  @Autowired
  private PasswordGeneratorRequestTranslator subject;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      when(secretGenerator.generateSecret(any(PasswordGenerationParameters.class))).thenReturn(new Password("my-password"));
    });

    it("returns a StringGeneratorRequest for valid json", () -> {
      String json = "{\"type\":\"password\"}";
      PasswordGenerationParameters params = subject.validRequestParameters(jsonPath.parse(json), null);
      PasswordGenerationParameters expectedParameters = new PasswordGenerationParameters();
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    itThrowsWithMessage("rejects excluding all possible character sets as an invalid case", ParameterizedValidationException.class, "error.excludes_all_charsets", () -> {
      String json = "{" +
          "\"type\":\"password\"," +
          "\"parameters\": {" +
          "\"only_hex\": false," +
          "\"exclude_special\": true," +
          "\"exclude_number\": true," +
          "\"exclude_upper\": true," +
          "\"exclude_lower\": true," +
          "\"length\": 42" +
          "}" +
          "}";
      subject.validRequestParameters(jsonPath.parse(json), null);
    });


    itThrowsWithMessage("rejects any parameters given in addition to name and regenerate", ParameterizedValidationException.class, "error.invalid_regenerate_parameters", () -> {
      String json = "{" +
          "  \"type\":\"password\"," +
          "  \"name\":\"foo\"," +
          "  \"regenerate\":true" +
          "}";
      subject.validRequestParameters(jsonPath.parse(json), null);
    });


    it("can populate an entity from JSON", () -> {
      final NamedPasswordSecret secret = new NamedPasswordSecret("abc");

      String requestJson = "{" +
          "  \"type\":\"password\"," +
          "  \"parameters\":{" +
          "    \"length\":11," +
          "    \"exclude_upper\":true" +
          "  }" +
          "}";
      DocumentContext parsed = jsonPath.parse(requestJson);
      subject.populateEntityFromJson(secret, parsed);
      assertThat(secret.getValue(), notNullValue());
      assertThat(secret.getGenerationParameters().getLength(), equalTo(11));
      assertThat(secret.getGenerationParameters().isExcludeLower(), equalTo(false));
      assertThat(secret.getGenerationParameters().isExcludeUpper(), equalTo(true));
    });


    it("can populate a hex-only entity from JSON", () -> {
      final NamedPasswordSecret secret = new NamedPasswordSecret("abc");
      secret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());

      String requestJson = "{" +
          "  \"type\":\"password\"," +
          "  \"parameters\":{" +
          "    \"length\":11," +
          "    \"only_hex\":true" +
          "  }" +
          "}";
      DocumentContext parsed = jsonPath.parse(requestJson);
      subject.populateEntityFromJson(secret, parsed);
      assertThat(secret.getValue(), notNullValue());
      assertThat(secret.getGenerationParameters().getLength(), equalTo(11));
      assertThat(secret.getGenerationParameters().isOnlyHex(), equalTo(true));
    });

    it("can regenerate using the existing entity and json", () -> {
      PasswordGenerationParameters generationParameters = new PasswordGenerationParameters();

      NamedPasswordSecret secret = new NamedPasswordSecret("test");
      secret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
      secret.setValue("old-password");
      secret.setGenerationParameters(generationParameters);

      subject.populateEntityFromJson(secret, jsonPath.parse("{\"regenerate\":true}"));

      when(secretGenerator.generateSecret(generationParameters)).thenReturn(new Password("my-password"));

      assertThat(secret.getValue(), equalTo("my-password"));
    });

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{" +
            "\"type\":\"password\"," +
            "\"overwrite\":false," +
            "\"name\":\"eggbert\"," +
            "\"regenerate\":true," +
            "\"parameters\":{" +
            "\"length\":3," +
            "\"exclude_lower\":true" +
            "\"exclude_upper\":true" +
            "\"exclude_number\":true" +
            "\"exclude_special\":true" +
            "\"only_hex\":true" +
            "}" +
            "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        //pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"password\",\"foo\":\"invalid\"}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });

    itThrowsWithMessage("rejects generation unless generation parameters are present in the existing entity", ParameterizedValidationException.class, "error.cannot_regenerate_non_generated_credentials", () -> {
      NamedPasswordSecret secretWithoutGenerationParameters = new NamedPasswordSecret("test");
      secretWithoutGenerationParameters.setValue("old-password");

      subject.validRequestParameters(jsonPath.parse("{\"regenerate\":true}"), secretWithoutGenerationParameters);
    });
  }
}
