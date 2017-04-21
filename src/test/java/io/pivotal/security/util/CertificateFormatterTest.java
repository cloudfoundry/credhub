package io.pivotal.security.util;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.core.StringStartsWith.startsWith;

@RunWith(Spectrum.class)
public class CertificateFormatterTest {

  private KeyPair keyPair;

  {
    beforeEach(() -> {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPair = keyPairGenerator.generateKeyPair();
    });

    describe("pemOf", () -> {
      it("should convert an object to a pem string", () -> {
        String pemString = CertificateFormatter.pemOf(keyPair);
        assertThat(pemString, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
        assertThat(pemString, endsWith("-----END RSA PRIVATE KEY-----\n"));
      });
    });

    describe("derOf", () -> {
      it("should convert an object to a DER encoded string", () -> {
        keyPair.getPublic().toString();
        String pemString = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic());
        assertThat(pemString, startsWith("ssh-rsa "));
      });
    });
  }

}
