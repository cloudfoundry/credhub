package io.pivotal.security.mapper;


import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.controller.v1.StringSecretParameters;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.StringSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class PasswordGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

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
      StringSecretParameters params = subject.validRequestParameters(JsonPath.using(configuration).parse(json));
      StringSecretParameters expectedParameters = new StringSecretParameters();
      expectedParameters.setType("password");
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    it("rejects excluding all possible character sets as an invalid case", () -> {
      String json = "{" +
          "\"type\":\"password\"," +
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
      } catch (ParameterizedValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.excludes_all_charsets"));
      }
    });

    it("can populate an entity from JSON", () -> {
      final NamedPasswordSecret secret = new NamedPasswordSecret("abc");

      String requestJson = "{\"type\":\"password\"}";
      DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
      subject.populateEntityFromJson(secret, parsed);
      assertThat(secret.getValue(), notNullValue());
    });
  }
}
