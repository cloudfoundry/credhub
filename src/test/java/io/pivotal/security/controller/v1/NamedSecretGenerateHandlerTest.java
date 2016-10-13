package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.*;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.RsaGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.*;

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
  SecretRepository secretRepository;

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
          SecretKind.VALUE.map(subject.make("secret-path", documentContext)).apply(null);
        });

        itThrowsWithMessage("ignores type mismatches and gives the can't generate message", ParameterizedValidationException.class, "error.invalid_generate_type", () -> {
          SecretKind.VALUE.map(subject.make("secret-path", documentContext)).apply(new NamedPasswordSecret());
        });
      });

      describe("password", behavesLikeMapper(() -> subject, () -> subject.passwordGeneratorRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

      describe("certificate", behavesLikeMapper(() -> subject, () -> subject.certificateGeneratorRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));

      describe("ssh", behavesLikeMapper(() -> subject, () -> subject.sshGeneratorRequestTranslator, SecretKind.SSH, NamedSshSecret.class, new NamedCertificateSecret(), new NamedSshSecret()));

      describe("rsa", behavesLikeMapper(() -> subject, () -> subject.rsaGeneratorRequestTranslator, SecretKind.RSA, NamedRsaSecret.class, new NamedCertificateSecret(), new NamedRsaSecret()));
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
}
