package io.pivotal.security.generator;

import io.pivotal.security.jna.libcrypto.CryptoWrapper;
import io.pivotal.security.service.BcEncryptionService;
import io.pivotal.security.service.PasswordKeyProxyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;

import static io.pivotal.security.helper.TestHelper.getBouncyCastleProvider;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(JUnit4.class)
public class LibcryptoRsaKeyPairGeneratorTest {
  private LibcryptoRsaKeyPairGenerator subject;

  @Before
  public void beforeEach() throws Exception {
    BouncyCastleProvider bouncyCastleProvider = getBouncyCastleProvider();
    BcEncryptionService encryptionService = new BcEncryptionService(bouncyCastleProvider, mock(PasswordKeyProxyFactory.class));

    subject = new LibcryptoRsaKeyPairGenerator(new CryptoWrapper(bouncyCastleProvider, encryptionService));
  }

  @Test
  public void generateKeyPair_generatesKeyPair() throws InvalidKeySpecException, InvalidKeyException {
    KeyPair keyPair = subject.generateKeyPair(2048);

    assertThat(keyPair.getPublic(), notNullValue());
    assertThat(keyPair.getPrivate(), notNullValue());
  }
}
