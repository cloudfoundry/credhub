package io.pivotal.security.mapper;


import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.StringSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class PasswordGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @Mock
  SecretGenerator secretGenerator;

  @InjectMocks
  private PasswordGeneratorRequestTranslator subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(secretGenerator.generateSecret(any(RequestParameters.class))).thenReturn(new StringSecret("password", "my-password"));
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

    itThrowsWithMessage("rejects any parameters given in addition to regenerate", ParameterizedValidationException.class, "error.invalid_regenerate_parameters", () -> {
      String json = "{" +
          "  \"type\":\"password\"," +
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

      NamedPasswordSecret secret = new NamedPasswordSecret("test", "old-password", generationParameters);

      subject.populateEntityFromJson(secret, jsonPath.parse("{\"regenerate\":true}"));

      when(secretGenerator.generateSecret(generationParameters)).thenReturn(new StringSecret("password", "my-password"));

      assertThat(secret.getValue(), equalTo("my-password"));
    });
  }
}
