package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RsaSshSetRequestTranslator;
import io.pivotal.security.mapper.StringSetRequestTranslator;
import io.pivotal.security.util.DatabaseProfileResolver;
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
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedSecretSetHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  @Autowired
  NamedSecretSetHandler subject;

  @Autowired
  ParseContext jsonPath;

  @MockBean
  private StringSetRequestTranslator stringSetRequestTranslator;

  @MockBean
  private CertificateSetRequestTranslator certificateSetRequestTranslator;

  @MockBean
  private RsaSshSetRequestTranslator rsaSshSetRequestTranslator;

  {
    wireAndUnwire(this, false);

    describe("it verifies the secret type and secret creation for", () -> {
      beforeEach(injectMocks(this));

      describe(
          "value",
          behavesLikeMapper(() -> subject,
              () -> subject.stringSetRequestTranslator,
              SecretKind.VALUE,
              NamedValueSecret.class,
              new NamedValueSecret(),
              mock(NamedValueSecret.class))
      );

      describe(
          "password",
          behavesLikeMapper(() -> subject,
              () -> subject.stringSetRequestTranslator,
              SecretKind.PASSWORD,
              NamedPasswordSecret.class,
              new NamedPasswordSecret(),
              mock(NamedPasswordSecret.class))
      );

      describe(
          "certificate",
          behavesLikeMapper(() -> subject,
              () -> subject.certificateSetRequestTranslator,
              SecretKind.CERTIFICATE,
              NamedCertificateSecret.class,
              new NamedCertificateSecret(),
              mock(NamedCertificateSecret.class))
      );

      describe(
          "ssh",
          behavesLikeMapper(() -> subject,
              () -> subject.rsaSshSetRequestTranslator,
              SecretKind.SSH,
              NamedSshSecret.class,
              new NamedSshSecret(),
              mock(NamedSshSecret.class))
      );

      describe(
          "rsa",
          behavesLikeMapper(() -> subject,
              () -> subject.rsaSshSetRequestTranslator,
              SecretKind.RSA,
              NamedRsaSecret.class,
              new NamedRsaSecret(),
              mock(NamedRsaSecret.class))
      );
    });

    describe("verifies full set of keys for", () -> {

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

  @Override
  protected void verifyExistingSecretCopying(NamedSecret mockExistingSecret) {
    verify(mockExistingSecret, never()).copyInto(any());
  }
}
