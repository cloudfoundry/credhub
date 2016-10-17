package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.controller.v1.SshSecretParametersFactory;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SshSecret;
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
public class SshGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @Mock
  SshGenerator secretGenerator;

  @Mock
  SshSecretParametersFactory sshSecretParametersFactory;

  @InjectMocks
  private SshGeneratorRequestTranslator subject;

  private SshSecretParameters mockParams;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockParams = spy(SshSecretParameters.class);
      when(sshSecretParametersFactory.get()).thenReturn(mockParams);
    });

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{\"" +
            "type\":\"ssh\"," +
            "\"overwrite\":false," +
            "\"parameters\":{" +
              "\"key_length\":3072," +
              "\"ssh_comment\":\"commentcommentcomment\"" +
            "}" +
            "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        //pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"ssh\",\"foo\":\"invalid\"}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });

    describe("populateEntityFromJson", () -> {
      beforeEach(() -> {
        when(secretGenerator.generateSecret(any(SshSecretParameters.class)))
            .thenReturn(new SshSecret(null, null, "my-public", "my-private"));
      });

      it("populates an entity", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(secretGenerator).generateSecret(mockParams);

        assertThat(namedSshSecret.getPrivateKey(), equalTo("my-private"));
        assertThat(namedSshSecret.getPublicKey(), equalTo("my-public"));
      });

      it("validates the parameters", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(mockParams, times(1)).validate();
      });

      it("accepts parameters", () -> {
        String json = "{" +
            "\"type\":\"ssh\"," +
            "\"parameters\":{" +
              "\"key_length\":3072," +
              "\"ssh_comment\":\"this is an ssh comment\"" +
            "}" +
          "}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(mockParams).setKeyLength(3072);
        verify(mockParams).setSshComment("this is an ssh comment");

        verify(secretGenerator).generateSecret(mockParams);
      });
    });
  }
}
