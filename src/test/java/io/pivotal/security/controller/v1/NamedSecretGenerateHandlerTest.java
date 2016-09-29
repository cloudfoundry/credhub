package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class NamedSecretGenerateHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  @InjectMocks
  NamedSecretGenerateHandler subject;

  @Autowired
  NamedSecretGenerateHandler realSubject;

  @Autowired
  Configuration configuration;

  @Mock
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

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
    });

    describe("verifies full set of keys for", () -> {
      wireAndUnwire(this);

      it("password", validateJsonKeys(() -> realSubject.passwordGeneratorRequestTranslator,
          "{\"type\":\"password\"," +
          "\"overwrite\":true," +
          "\"parameters\":{\"length\":2048," +
              "\"exclude_lower\":true," +
              "\"exclude_upper\":false," +
              "\"exclude_number\":false," +
              "\"exclude_special\":false}}"));

      it("certificate", validateJsonKeys(() -> realSubject.certificateGeneratorRequestTranslator,
        "{\"type\":\"certificate\"," +
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
            "}}"));
    });
  }
}