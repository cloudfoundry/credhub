package org.cloudfoundry.credhub.generator;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;

import org.cloudfoundry.credhub.jna.libcrypto.CryptoWrapper;
import org.cloudfoundry.credhub.service.RandomNumberGenerator;
import org.cloudfoundry.credhub.util.PseudoRandomNumberGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class LibcryptoRsaKeyPairGeneratorTest {
  private LibcryptoRsaKeyPairGenerator subject;

  @Before
  public void beforeEach() throws Exception {
    final RandomNumberGenerator randomNumberGenerator = new PseudoRandomNumberGenerator();

    subject = new LibcryptoRsaKeyPairGenerator(new CryptoWrapper(randomNumberGenerator));
  }

  @Test
  public void generateKeyPair_generatesKeyPair() throws InvalidKeySpecException, InvalidKeyException {
    final KeyPair keyPair = subject.generateKeyPair(2048);

    assertThat(keyPair.getPublic(), notNullValue());
    assertThat(keyPair.getPrivate(), notNullValue());
  }
}
