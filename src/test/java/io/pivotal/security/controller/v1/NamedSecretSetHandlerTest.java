package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.*;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RsaSshSetRequestTranslator;
import io.pivotal.security.mapper.StringSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class NamedSecretSetHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  @InjectMocks
  NamedSecretSetHandler subject;

  @Autowired
  NamedSecretSetHandler realSubject;

  @Autowired
  ParseContext jsonPath;

  @Mock
  StringSetRequestTranslator stringSetRequestTranslator;

  @Mock
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  @Mock
  RsaSshSetRequestTranslator rsaSshSetRequestTranslator;

  {
    describe("it verifies the secret type and secret creation for", () -> {
      beforeEach(injectMocks(this));

      describe("value", behavesLikeMapper(() -> subject, () -> subject.stringSetRequestTranslator, SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret(), new NamedValueSecret()));

      describe("password", behavesLikeMapper(() -> subject, () -> subject.stringSetRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

      describe("certificate", behavesLikeMapper(() -> subject, () -> subject.certificateSetRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));

      describe("ssh", behavesLikeMapper(() -> subject, () -> subject.rsaSshSetRequestTranslator, SecretKind.SSH, NamedSshSecret.class, new NamedPasswordSecret(), new NamedSshSecret()));

      describe("rsa", behavesLikeMapper(() -> subject, () -> subject.rsaSshSetRequestTranslator, SecretKind.RSA, NamedRsaSecret.class, new NamedPasswordSecret(), new NamedRsaSecret()));
    });

    describe("verifies full set of keys for", () -> {
      wireAndUnwire(this);

      it("value", () -> {
        stringSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"value\",\"value\":\"myValue\",\"overwrite\":true}"));
      });

      it("password", () -> {
        stringSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"password\",\"value\":\"myValue\",\"overwrite\":true}"));
      });

      it("certificate", () -> {
        certificateSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"certificate\"," +
            "\"overwrite\":true," +
            "\"value\":{" +
            "\"ca\":\"ca\"," +
            "\"certificate\":\"cert\"," +
            "\"private_key\":\"pk\"}}"));
      });

      it("ssh", () -> {
        rsaSshSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"ssh\"," +
            "\"overwrite\":true," +
            "\"value\":{" +
            "\"public_key\":\"public-key\"," +
            "\"private_key\":\"private-key\"}}"));
      });

      it("rsa", () -> {
        rsaSshSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"rsa\"," +
            "\"overwrite\":true," +
            "\"value\":{" +
            "\"public_key\":\"public-key\"," +
            "\"private_key\":\"private-key\"}}"));
      });
    });
  }
}
