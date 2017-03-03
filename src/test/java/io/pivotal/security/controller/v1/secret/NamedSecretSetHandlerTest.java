package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RsaSshSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class NamedSecretSetHandlerTest extends AbstractNamedSecretHandlerTestingUtil {

  private NamedSecretSetHandler subject;
  private ParseContext jsonPath;
  private CertificateSetRequestTranslator certificateSetRequestTranslator = mock(CertificateSetRequestTranslator.class);
  private RsaSshSetRequestTranslator rsaSshSetRequestTranslator = mock(RsaSshSetRequestTranslator.class);
  private Encryptor encryptor = mock(Encryptor.class);

  {
    beforeEach(() -> {
      jsonPath = new JsonContextFactory().getObject();
      subject = new NamedSecretSetHandler(
          certificateSetRequestTranslator,
          rsaSshSetRequestTranslator,
          encryptor
        );
    });

    describe("it verifies the secret type and secret creation for", () -> {
      describe(
          "certificate",
          behavesLikeMapper(() -> subject,
              certificateSetRequestTranslator,
              SecretKind.CERTIFICATE,
              NamedCertificateSecret.class,
              new NamedCertificateSecret()
          )
      );

      describe(
          "ssh",
          behavesLikeMapper(() -> subject,
              rsaSshSetRequestTranslator,
              SecretKind.SSH,
              NamedSshSecret.class,
              new NamedSshSecret()
          )
      );

      describe(
          "rsa",
          behavesLikeMapper(() -> subject,
              rsaSshSetRequestTranslator,
              SecretKind.RSA,
              NamedRsaSecret.class,
              new NamedRsaSecret()
          )
      );
    });

    describe("verifies full set of keys for", () -> {
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
