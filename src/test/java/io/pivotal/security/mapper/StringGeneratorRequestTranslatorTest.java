package io.pivotal.security.mapper;


import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.controller.v1.StringSecretParameters;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.StringSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

import javax.validation.ValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class StringGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  @Mock
  SecretGenerator secretGenerator;

  @InjectMocks
  private StringGeneratorRequestTranslator subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(secretGenerator.generateSecret(any(RequestParameters.class))).thenReturn(new StringSecret("my-password"));
    });

    it("returns a StringGeneratorRequest for valid json", () -> {
      String json = "{\"type\":\"value\"}";
      StringSecretParameters params = subject.validRequestParameters(JsonPath.using(configuration).parse(json));
      StringSecretParameters expectedParameters = new StringSecretParameters();
      expectedParameters.setType("value");
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
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
        subject.validRequestParameters(JsonPath.using(configuration).parse(json));
        fail();
      } catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.excludes_all_charsets"));
      }
    });

    it("can make an entity", () -> {
      final NamedStringSecret secret = subject.makeEntity("abc");
      assertThat(secret.getName(), equalTo("abc"));
    });

    it("can populate an entity from JSON", () -> {
      final NamedStringSecret secret = subject.makeEntity("abc");

      String requestJson = "{\"type\":\"value\"}";
      DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
      subject.populateEntityFromJson(secret, parsed);
      assertThat(secret.getValue(), notNullValue());
    });
  }
}
