package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.jna.libcrypto.CryptoWrapper;
import org.cloudfoundry.credhub.service.InternalEncryptionService;
import org.cloudfoundry.credhub.service.PasswordKeyProxyFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(JUnit4.class)
public class LibcryptoRsaKeyPairGeneratorTest {
  private LibcryptoRsaKeyPairGenerator subject;

  @Before
  public void beforeEach() throws Exception {
    InternalEncryptionService encryptionService = new InternalEncryptionService(mock(PasswordKeyProxyFactory.class));

    subject = new LibcryptoRsaKeyPairGenerator(new CryptoWrapper(encryptionService));
  }

  @Test
  public void generateKeyPair_generatesKeyPair() throws InvalidKeySpecException, InvalidKeyException {
    KeyPair keyPair = subject.generateKeyPair(2048);

    assertThat(keyPair.getPublic(), notNullValue());
    assertThat(keyPair.getPrivate(), notNullValue());
  }
}
