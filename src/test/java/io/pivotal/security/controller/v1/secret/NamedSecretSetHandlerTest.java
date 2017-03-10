package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.AbstractNamedSecretHandlerTestingUtil;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RsaSetRequestTranslator;
import io.pivotal.security.mapper.SshSetRequestTranslator;
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
  private SshSetRequestTranslator sshSetRequestTranslator = mock(SshSetRequestTranslator.class);
  private RsaSetRequestTranslator rsaSetRequestTranslator = mock(RsaSetRequestTranslator.class);
  private Encryptor encryptor = mock(Encryptor.class);

  {
    beforeEach(() -> {
      jsonPath = new JsonContextFactory().getObject();
      subject = new NamedSecretSetHandler(
          certificateSetRequestTranslator,
          sshSetRequestTranslator,
          rsaSetRequestTranslator,
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
              sshSetRequestTranslator,
              SecretKind.SSH,
              NamedSshSecret.class,
              new NamedSshSecret()
          )
      );

      describe(
          "rsa",
          behavesLikeMapper(() -> subject,
              rsaSetRequestTranslator,
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
        rsaSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"ssh\"," +
            "\"overwrite\":true," +
            "\"value\":{" +
            "\"public_key\":\"public-key\"," +
            "\"private_key\":\"private-key\"}}"));
      });

      it("rsa", () -> {
        rsaSetRequestTranslator.validateJsonKeys(jsonPath.parse("{\"type\":\"rsa\"," +
            "\"overwrite\":true," +
            "\"value\":{" +
            "\"public_key\":\"public-key\"," +
            "\"private_key\":\"private-key\"}}"));
      });
    });
  }
}
