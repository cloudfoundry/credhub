package io.pivotal.security.mapper;


import com.greghaskins.spectrum.SpringSpectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.StringGeneratorRequest;
import io.pivotal.security.validator.GeneratorRequestValidator;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import javax.validation.ValidationException;

import static com.greghaskins.spectrum.SpringSpectrum.beforeEach;
import static com.greghaskins.spectrum.SpringSpectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(SpringSpectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class StringGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  private StringGeneratorRequestTranslator subject;

  {
    beforeEach(() -> {
      GeneratorRequestValidator validator = new GeneratorRequestValidator();
      subject = new StringGeneratorRequestTranslator(validator);
    });

    it("returns a StringGeneratorRequest for valid json", () -> {
      String json = "{\"type\":\"value\"}";
      StringGeneratorRequest generatorRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
      assertThat(generatorRequest.getType(), equalTo("value"));
    });

    it("rejects excluding all possible character sets as an invalid case", () -> {
      String json = "{" +
          "\"type\":\"value\"," +
          "\"parameters\": {" +
            "\"exclude_special\": true," +
            "\"exclude_number\": true," +
            "\"exclude_upper\": true," +
            "\"exclude_lower\": true," +
            "\"length\": 42" +
            "}" +
          "}";
      try {
        subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
        fail();
      } catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.excludes_all_charsets"));
      }
    });

    it("rejects an unknown type", () -> {
      String json = "{\"type\":\"foo\"}";
      try {
        subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
        fail();
      } catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.secret_type_invalid"));
      }
    });

    it("rejects empty json", () -> {
      String json = "{}";
      try {
        subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
        fail();
      } catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.secret_type_invalid"));
      }
    });
  }
}
