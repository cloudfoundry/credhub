package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.RsaGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class NamedSecretGenerateHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  private NamedSecretGenerateHandler subject;
  private ParseContext jsonPath;
  private CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator = mock(
      CertificateGeneratorRequestTranslator.class);
  private SshGeneratorRequestTranslator sshGeneratorRequestTranslator = mock(
      SshGeneratorRequestTranslator.class);
  private RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator = mock(
      RsaGeneratorRequestTranslator.class);
  private Encryptor encryptor = mock(Encryptor.class);

  {
    beforeEach(() -> {
      jsonPath = new JsonContextFactory().getParseContext();
      subject = new NamedSecretGenerateHandler(
          certificateGeneratorRequestTranslator,
          sshGeneratorRequestTranslator,
          rsaGeneratorRequestTranslator,
          encryptor
      );
    });

    describe("it verifies the secret type and secret creation for", () -> {
      describe("value", () -> {
        itThrowsWithMessage("cannot be generated", ParameterizedValidationException.class,
            "error.invalid_type_with_generate_prompt", () -> {
              SecretKind.VALUE.lift(subject.make("secret-path", null)).apply(null);
            });

        itThrowsWithMessage("ignores type mismatches and gives the can't generate message",
            ParameterizedValidationException.class, "error.invalid_type_with_generate_prompt",
            () -> {
              SecretKind.VALUE.lift(subject.make("secret-path", null))
                  .apply(new NamedPasswordSecret());
            });
      });

      describe(
          "certificate",
          behavesLikeMapper(() -> subject,
              certificateGeneratorRequestTranslator,
              SecretKind.CERTIFICATE,
              NamedCertificateSecret.class,
              new NamedCertificateSecret()
          )
      );

      describe(
          "ssh",
          behavesLikeMapper(() -> subject,
              sshGeneratorRequestTranslator,
              SecretKind.SSH,
              NamedSshSecret.class,
              new NamedSshSecret()
          )
      );

      describe(
          "rsa",
          behavesLikeMapper(() -> subject,
              rsaGeneratorRequestTranslator,
              SecretKind.RSA,
              NamedRsaSecret.class,
              new NamedRsaSecret()
          )
      );
    });

    describe("verifies full set of keys for", () -> {

      it("certificate", () -> {
            certificateGeneratorRequestTranslator
                .validateJsonKeys(jsonPath.parse("{\"type\":\"certificate\","
                    + "\"overwrite\":true,"
                    + "\"parameters\":{"
                    + "\"common_name\":\"My Common Name\", "
                    + "\"organization\": \"organization.io\","
                    + "\"organization_unit\": \"My Unit\","
                    + "\"locality\": \"My Locality\","
                    + "\"state\": \"My State\","
                    + "\"country\": \"My Country\","
                    + "\"key_length\": 3072,"
                    + "\"duration\": 1000,"
                    + "\"alternative_names\": [],"
                    + "\"ca\": \"default\","
                    + "}"
                    + "}"));
          }
      );

      it("ssh", () -> {
            sshGeneratorRequestTranslator.validateJsonKeys(jsonPath.parse("{"
                + "\"type\":\"ssh\","
                + "\"overwrite\":true,"
                + "\"parameters\":{"
                + "\"key_length\":3072,"
                + "\"ssh_comment\":\"ssh comment\""
                + "}"
                + "}"));
          }
      );

      it("rsa", () -> {
            rsaGeneratorRequestTranslator.validateJsonKeys(jsonPath.parse("{"
                + "\"type\":\"rsa\","
                + "\"overwrite\":true,"
                + "\"parameters\":{"
                + "\"key_length\":2048"
                + "}"
                + "}"));
          }
      );
    });
  }
}
