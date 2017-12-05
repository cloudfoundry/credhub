package org.cloudfoundry.credhub.util;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.core.StringStartsWith.startsWith;

@RunWith(JUnit4.class)
public class CertificateFormatterTest {
  private KeyPair keyPair;

  @Before
  public void beforeEach() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

    keyPair = keyPairGenerator.generateKeyPair();
  }

  @Test
  public void pemOf_convertsAnObjectToPemString() throws IOException {
    String pemString = CertificateFormatter.pemOf(keyPair);

    assertThat(pemString, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
    assertThat(pemString, endsWith("-----END RSA PRIVATE KEY-----\n"));
  }

  @Test
  public void derOf_convertsObjectToDerEncodedString() throws IOException {
    keyPair.getPublic().toString();

    String pemString = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic());
    assertThat(pemString, startsWith("ssh-rsa "));
  }
}
