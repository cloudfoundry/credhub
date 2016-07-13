package io.pivotal.security.mapper;


import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.GeneratorRequest;
import io.pivotal.security.controller.v1.StringSecretParameters;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import javax.validation.ValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class StringGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  private StringGeneratorRequestTranslator subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new StringGeneratorRequestTranslator();
    });

    it("returns a StringGeneratorRequest for valid json", () -> {
      String json = "{\"type\":\"value\"}";
      GeneratorRequest<StringSecretParameters> generatorRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
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
  }
}
