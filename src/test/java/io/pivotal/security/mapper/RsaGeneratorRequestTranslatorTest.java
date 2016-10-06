package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.controller.v1.RsaSecretParametersFactory;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.generator.BCRsaGenerator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.RsaSecret;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class RsaGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  @Mock
  BCRsaGenerator secretGenerator;

  @Mock
  RsaSecretParametersFactory rsaSecretParametersFactory;

  @InjectMocks
  private RsaGeneratorRequestTranslator subject;

  private RsaSecretParameters mockParams;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockParams = spy(RsaSecretParameters.class);
      when(rsaSecretParametersFactory.get()).thenReturn(mockParams);
    });

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{\"" +
            "type\":\"ssh\"," +
            "\"overwrite\":false," +
            "\"parameters\":{" +
              "\"key_length\":3072" +
            "}" +
            "}";
        DocumentContext parsed = JsonPath.using(configuration).parse(requestBody);

        subject.validateJsonKeys(parsed);
        //pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"ssh\",\"foo\":\"invalid\"}";
        DocumentContext parsed = JsonPath.using(configuration).parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });

    describe("populateEntityFromJson", () -> {
      beforeEach(() -> {
        when(secretGenerator.generateSecret(any(RsaSecretParameters.class)))
            .thenReturn(new RsaSecret(null, null, "my-public", "my-private"));
      });

      it("populates an entity", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = JsonPath.using(configuration).parse(json);

        NamedRsaSecret namedRsaSecret = new NamedRsaSecret();
        subject.populateEntityFromJson(namedRsaSecret, parsed);

        verify(secretGenerator).generateSecret(mockParams);

        assertThat(namedRsaSecret.getPrivateKey(), equalTo("my-private"));
        assertThat(namedRsaSecret.getPublicKey(), equalTo("my-public"));
      });

      it("validates the parameters", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = JsonPath.using(configuration).parse(json);

        NamedRsaSecret namedRsaSecret = new NamedRsaSecret();
        subject.populateEntityFromJson(namedRsaSecret, parsed);

        verify(mockParams, times(1)).validate();
      });

      it("accepts a key-length", () -> {
        String json = "{" +
            "\"type\":\"ssh\"," +
            "\"parameters\":{" +
              "\"key_length\":3072" +
            "}" +
          "}";
        DocumentContext parsed = JsonPath.using(configuration).parse(json);

        NamedRsaSecret namedRsaSecret = new NamedRsaSecret();
        subject.populateEntityFromJson(namedRsaSecret, parsed);

        verify(mockParams).setKeyLength(3072);

        verify(secretGenerator).generateSecret(mockParams);
      });
    });
  }
}
