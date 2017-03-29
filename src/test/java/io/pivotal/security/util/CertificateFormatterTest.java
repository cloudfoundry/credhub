package io.pivotal.security.util;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.core.StringStartsWith.startsWith;

import com.greghaskins.spectrum.Spectrum;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class CertificateFormatterTest {

  private KeyPair someSecret;

  {
    beforeEach(() -> {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      someSecret = keyPairGenerator.generateKeyPair();
    });

    describe("pemOf", () -> {
      it("should convert an object to a pem string", () -> {
        String pemString = CertificateFormatter.pemOf(someSecret);
        assertThat(pemString, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
        assertThat(pemString, endsWith("-----END RSA PRIVATE KEY-----\n"));
      });
    });

    describe("derOf", () -> {
      it("should convert an object to a DER encoded string", () -> {
        someSecret.getPublic().toString();
        String pemString = CertificateFormatter.derOf((RSAPublicKey) someSecret.getPublic());
        assertThat(pemString, startsWith("ssh-rsa "));
      });
    });
  }

}
