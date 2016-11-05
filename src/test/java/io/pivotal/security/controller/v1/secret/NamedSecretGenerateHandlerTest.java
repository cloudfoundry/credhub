package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.RsaGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

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
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class NamedSecretGenerateHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  @InjectMocks
  NamedSecretGenerateHandler subject;

  @Autowired
  NamedSecretGenerateHandler realSubject;

  @Autowired
  ParseContext jsonPath;

  @Autowired
  SecretDataService secretDataService;

  @Mock
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Mock
  SshGeneratorRequestTranslator sshGeneratorRequestTranslator;

  @Mock
  RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator;

  @Mock
  DocumentContext documentContext;

  {
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
      wireAndUnwire(this);

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
