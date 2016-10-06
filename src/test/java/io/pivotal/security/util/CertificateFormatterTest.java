package io.pivotal.security.util;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import static com.greghaskins.spectrum.Spectrum.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.core.StringStartsWith.startsWith;

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
