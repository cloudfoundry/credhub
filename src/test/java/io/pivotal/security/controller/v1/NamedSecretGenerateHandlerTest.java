package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.ValueGeneratorRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;

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
  ValueGeneratorRequestTranslator valueGeneratorRequestTranslator;

  @Mock
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  {
    describe("it verifies the secret type and secret creation for", () -> {
      beforeEach(injectMocks(this));

      describe("value", behavesLikeMapper(() -> subject, () -> subject.valueGeneratorRequestTranslator, SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret(), new NamedValueSecret()));

      describe("password", behavesLikeMapper(() -> subject, () -> subject.passwordGeneratorRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

      describe("certificate", behavesLikeMapper(() -> subject, () -> subject.certificateGeneratorRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));
    });

    describe("verifies full set of keys for", () -> {
      wireAndUnwire(this);

      it("value", validateJsonKeys(() -> realSubject.valueGeneratorRequestTranslator,
          "{\"type\":\"value\"," +
          "\"overwrite\":true," +
          "\"parameters\":{\"length\":2048," +
              "\"exclude_lower\":true," +
              "\"exclude_upper\":false," +
              "\"exclude_number\":false," +
              "\"exclude_special\":false}}"));

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