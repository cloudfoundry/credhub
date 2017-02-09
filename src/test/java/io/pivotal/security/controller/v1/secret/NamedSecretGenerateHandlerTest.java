package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.RsaGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedSecretGenerateHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  @Autowired
  NamedSecretGenerateHandler subject;

  @Autowired
  ParseContext jsonPath;

  @Autowired
  SecretDataService secretDataService;

  @MockBean
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @MockBean
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @MockBean
  SshGeneratorRequestTranslator sshGeneratorRequestTranslator;

  @MockBean
  RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator;

  @MockBean
  DocumentContext documentContext;

  {
    wireAndUnwire(this, false);

    describe("it verifies the secret type and secret creation for", () -> {
      beforeEach(injectMocks(this));

      describe("value", () -> {
        itThrowsWithMessage("cannot be generated", ParameterizedValidationException.class, "error.invalid_generate_type", () -> {
          SecretKind.VALUE.lift(subject.make("secret-path", documentContext)).apply(null);
        });

        itThrowsWithMessage("ignores type mismatches and gives the can't generate message", ParameterizedValidationException.class, "error.invalid_generate_type", () -> {
          SecretKind.VALUE.lift(subject.make("secret-path", documentContext)).apply(new NamedPasswordSecret());
        });
      });

      describe(
          "password",
          behavesLikeMapper(() -> subject,
              () -> subject.passwordGeneratorRequestTranslator,
              SecretKind.PASSWORD,
              NamedPasswordSecret.class,
              new NamedPasswordSecret(),
              mock(NamedPasswordSecret.class))
      );

      describe(
          "certificate",
          behavesLikeMapper(() -> subject,
              () -> subject.certificateGeneratorRequestTranslator,
              SecretKind.CERTIFICATE,
              NamedCertificateSecret.class,
              new NamedCertificateSecret(),
              mock(NamedCertificateSecret.class))
      );

      describe(
          "ssh",
          behavesLikeMapper(() -> subject,
              () -> subject.sshGeneratorRequestTranslator,
              SecretKind.SSH,
              NamedSshSecret.class,
              new NamedSshSecret(),
              mock(NamedSshSecret.class))
      );

      describe(
          "rsa",
          behavesLikeMapper(() -> subject,
              () -> subject.rsaGeneratorRequestTranslator,
              SecretKind.RSA,
              NamedRsaSecret.class,
              new NamedRsaSecret(),
              mock(NamedRsaSecret.class))
      );
    });

    describe("verifies full set of keys for", () -> {

      it("password", () -> {
            passwordGeneratorRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"password\"," +
                "\"overwrite\":true," +
                "\"regenerate\":true," +
                "\"parameters\":{\"length\":2048," +
                "\"exclude_lower\":true," +
                "\"exclude_upper\":false," +
                "\"exclude_number\":false," +
                "\"exclude_special\":false}" +
                "}"));
          }
      );

      it("certificate", () -> {
            certificateGeneratorRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"certificate\"," +
                "\"overwrite\":true," +
                "\"parameters\":{" +
                "\"common_name\":\"My Common Name\", " +
                "\"organization\": \"organization.io\"," +
                "\"organization_unit\": \"My Unit\"," +
                "\"locality\": \"My Locality\"," +
                "\"state\": \"My State\"," +
                "\"country\": \"My Country\"," +
                "\"key_length\": 3072," +
                "\"duration\": 1000," +
                "\"alternative_names\": []," +
                "\"ca\": \"default\"," +
                "}" +
                "}"));
          }
      );

      it("ssh", () -> {
            sshGeneratorRequestTranslator.validateJsonKeys(jsonPath.parse("{" +
                "\"type\":\"ssh\"," +
                "\"overwrite\":true," +
                "\"parameters\":{" +
                "\"key_length\":3072," +
                "\"ssh_comment\":\"ssh comment\"" +
                "}" +
                "}"));
          }
      );

      it("rsa", () -> {
            rsaGeneratorRequestTranslator.validateJsonKeys(jsonPath.parse("{" +
                "\"type\":\"rsa\"," +
                "\"overwrite\":true," +
                "\"parameters\":{" +
                "\"key_length\":2048" +
                "}" +
                "}"));
          }
      );
    });
  }

  @Override
  protected void verifyExistingSecretCopying(NamedSecret mockExistingSecret) {
    verify(mockExistingSecret).copyInto(any());
  }
}
