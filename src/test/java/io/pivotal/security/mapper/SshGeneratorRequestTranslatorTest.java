package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.generator.BCSshGenerator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SshSecret;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class SshGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  @Mock
  BCSshGenerator secretGenerator;

  @InjectMocks
  private SshGeneratorRequestTranslator subject;

  {
    wireAndUnwire(this);

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{\"type\":\"ssh\",\"overwrite\":false,\"parameters\":{}}";
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
        when(secretGenerator.generateSecret(any(SshSecretParameters.class)))
            .thenReturn(new SshSecret(null, null, "my-public", "my-private"));
      });

      it("populates an entity", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = JsonPath.using(configuration).parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(secretGenerator).generateSecret(isA(SshSecretParameters.class));

        assertThat(namedSshSecret.getPrivateKey(), equalTo("my-private"));
        assertThat(namedSshSecret.getPublicKey(), equalTo("my-public"));
      });
    });
  }
}
