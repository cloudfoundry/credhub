package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.controller.v1.RsaSecretParametersFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
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
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class RsaGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @MockBean
  RsaGenerator secretGenerator;

  @MockBean
  RsaSecretParametersFactory rsaSecretParametersFactory;

  @Autowired
  private RsaGeneratorRequestTranslator subject;

  private RsaSecretParameters mockParams;

  @Autowired
  private Encryptor encryptor;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockParams = spy(RsaSecretParameters.class);
      when(rsaSecretParametersFactory.get()).thenReturn(mockParams);
    });

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{" +
            "\"type\":\"rsa\"," +
            "\"name\":\"plugh\"," +
            "\"regenerate\": true," +
            "\"overwrite\":false," +
            "\"parameters\":{" +
              "\"key_length\":3072" +
            "}" +
            "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        //pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"rsa\",\"foo\":\"invalid\"}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });

    describe("populateEntityFromJson", () -> {
      beforeEach(() -> {
        when(secretGenerator.generateSecret(any(RsaSecretParameters.class)))
            .thenReturn(new RsaKey("my-public", "my-private"));
      });

      it("populates an entity", () -> {
        String json = "{\"type\":\"rsa\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedRsaSecret namedRsaSecret = new NamedRsaSecret();
        namedRsaSecret.setEncryptor(encryptor);
        subject.populateEntityFromJson(namedRsaSecret, parsed);

        verify(secretGenerator).generateSecret(mockParams);

        assertThat(namedRsaSecret.getPrivateKey(), equalTo("my-private"));
        assertThat(namedRsaSecret.getPublicKey(), equalTo("my-public"));
      });

      it("validates the parameters", () -> {
        String json = "{\"type\":\"rsa\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedRsaSecret namedRsaSecret = new NamedRsaSecret();
        namedRsaSecret.setEncryptor(encryptor);
        subject.populateEntityFromJson(namedRsaSecret, parsed);

        verify(mockParams, times(1)).validate();
      });

      it("accepts a key-length", () -> {
        String json = "{" +
            "\"type\":\"rsa\"," +
            "\"parameters\":{" +
              "\"key_length\":3072" +
            "}" +
          "}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedRsaSecret namedRsaSecret = new NamedRsaSecret();
        namedRsaSecret.setEncryptor(encryptor);
        subject.populateEntityFromJson(namedRsaSecret, parsed);

        verify(mockParams).setKeyLength(3072);

        verify(secretGenerator).generateSecret(mockParams);
      });

      it("can regenerate using the existing entity and JSON", () -> {
        NamedRsaSecret secret = spy(NamedRsaSecret.class);
        secret.setEncryptor(encryptor);
        secret.setSecretName(new SecretName("test"));
        when(secret.getKeyLength()).thenReturn(3072);

        ArgumentCaptor<RsaSecretParameters> parameterCaptor = ArgumentCaptor.forClass(RsaSecretParameters.class);
        when(secretGenerator.generateSecret(parameterCaptor.capture()))
            .thenReturn(new RsaKey("my-new-pub", "my-new-priv"));

        subject.populateEntityFromJson(secret, jsonPath.parse("{\"regenerate\":true}"));

        RsaSecretParameters requestParameters = parameterCaptor.getValue();
        assertThat(requestParameters.getKeyLength(), equalTo(3072));
        assertThat(secret.getPublicKey(), equalTo("my-new-pub"));
        assertThat(secret.getPrivateKey(), equalTo("my-new-priv"));
      });
    });
  }
}
