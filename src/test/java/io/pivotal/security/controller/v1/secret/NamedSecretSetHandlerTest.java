package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.PasswordSetRequestTranslator;
import io.pivotal.security.mapper.RsaSshSetRequestTranslator;
import io.pivotal.security.mapper.ValueSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
public class NamedSecretSetHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  private NamedSecretSetHandler subject;
  private ParseContext jsonPath;
  private ValueSetRequestTranslator valueSetRequestTranslator = mock(ValueSetRequestTranslator.class);
  private PasswordSetRequestTranslator passwordSetRequestTranslator = mock(PasswordSetRequestTranslator.class);
  private CertificateSetRequestTranslator certificateSetRequestTranslator = mock(CertificateSetRequestTranslator.class);
  private RsaSshSetRequestTranslator rsaSshSetRequestTranslator = mock(RsaSshSetRequestTranslator.class);
  private Encryptor encryptor = mock(Encryptor.class);

  {
    beforeEach(() -> {
      jsonPath = new JsonContextFactory().getObject();
      subject = new NamedSecretSetHandler(
          valueSetRequestTranslator,
          passwordSetRequestTranslator,
          certificateSetRequestTranslator,
          rsaSshSetRequestTranslator,
          encryptor
        );
    });

    describe("it verifies the secret type and secret creation for", () -> {
      describe(
          "value",
          behavesLikeMapper(() -> subject,
              valueSetRequestTranslator,
              SecretKind.VALUE,
              NamedValueSecret.class,
              new NamedValueSecret(),
              mock(NamedValueSecret.class))
      );

      describe(
          "password",
          behavesLikeMapper(() -> subject,
              passwordSetRequestTranslator,
              SecretKind.PASSWORD,
              NamedPasswordSecret.class,
              new NamedPasswordSecret(),
              mock(NamedPasswordSecret.class))
      );

      describe(
          "certificate",
          behavesLikeMapper(() -> subject,
              certificateSetRequestTranslator,
              SecretKind.CERTIFICATE,
              NamedCertificateSecret.class,
              new NamedCertificateSecret(),
              mock(NamedCertificateSecret.class))
      );

      describe(
          "ssh",
          behavesLikeMapper(() -> subject,
              rsaSshSetRequestTranslator,
              SecretKind.SSH,
              NamedSshSecret.class,
              new NamedSshSecret(),
              mock(NamedSshSecret.class))
      );

      describe(
          "rsa",
          behavesLikeMapper(() -> subject,
              rsaSshSetRequestTranslator,
              SecretKind.RSA,
              NamedRsaSecret.class,
              new NamedRsaSecret(),
              mock(NamedRsaSecret.class))
      );
    });

    describe("verifies full set of keys for", () -> {

      it("value", () -> {
        valueSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"value\",\"value\":\"myValue\",\"overwrite\":true}"));
      });

      it("password", () -> {
        valueSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"password\",\"value\":\"myValue\",\"overwrite\":true}"));
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
