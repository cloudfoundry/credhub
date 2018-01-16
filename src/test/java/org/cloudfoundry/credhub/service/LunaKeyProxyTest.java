package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.exceptions.IncorrectKeyException;
import org.cloudfoundry.credhub.util.PasswordKeyProxyFactoryTestImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.Key;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import static org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;

@RunWith(JUnit4.class)
public class LunaKeyProxyTest {
  private LunaKeyProxy subject;
  private Key encryptionKey;
  private EncryptionKeyCanary canary;
  private EncryptionKeyCanary deprecatedCanary;

  @Before
  public void beforeEach() throws Exception {
    final InternalEncryptionService encryptionService = new InternalEncryptionService(
        new PasswordKeyProxyFactoryTestImpl()
    );
    EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionPassword("p@ssword");

    encryptionKey = encryptionService.createKeyProxy(keyMetadata).getKey();
    canary = new EncryptionKeyCanary();
    EncryptedValue encryptionData = encryptionService.encrypt(null, encryptionKey, CANARY_VALUE);
    canary.setEncryptedCanaryValue(encryptionData.getEncryptedValue());
    canary.setNonce(encryptionData.getNonce());

    deprecatedCanary = new EncryptionKeyCanary();
    EncryptedValue deprecatedEncryptionData = encryptionService
        .encrypt(null, encryptionKey, DEPRECATED_CANARY_VALUE);
    deprecatedCanary.setEncryptedCanaryValue(deprecatedEncryptionData.getEncryptedValue());
    deprecatedCanary.setNonce(deprecatedEncryptionData.getNonce());
  }

  @Test
  public void isMatchingCanary_whenCanaryMatches_returnsTrue() throws Exception {
    subject = new LunaKeyProxy(encryptionKey, new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()));

    assertThat(subject.matchesCanary(canary), equalTo(true));
  }

  @Test
  public void isMatchingCanary_usingOldCanaryValue_returnsTrue() throws Exception {
    subject = new LunaKeyProxy(encryptionKey, new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()));

    assertThat(subject.matchesCanary(deprecatedCanary), equalTo(true));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsRelevantIllegalBlockSizeException_returnsFalse() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
        new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
          @Override
          public String decrypt(Key key, byte[] encryptedValue, byte[] nonce)
              throws Exception {
            throw new IllegalBlockSizeException("returns 0x40");
          }
        });

    assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsAEADBadTagException_returnsFalse() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
        new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
          @Override
          public String decrypt(Key key, byte[] encryptedValue, byte[] nonce)
              throws Exception {
            throw new AEADBadTagException();
          }
        });

    assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
  }

  @Test(expected = IncorrectKeyException.class)
  public void isMatchingCanary_whenDecryptThrowsBadPaddingException_throwsIncorrectKeyException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
        new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
          @Override
          public String decrypt(Key key, byte[] encryptedValue, byte[] nonce)
              throws Exception {
            throw new BadPaddingException("");
          }
        });

    subject.matchesCanary(mock(EncryptionKeyCanary.class));
  }

  @Test(expected = IncorrectKeyException.class)
  public void isMatchingCanary_whenDecryptThrowsIllegalBlockSizeException_throwsIncorrectKeyException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
        new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
          @Override
          public String decrypt(Key key, byte[] encryptedValue, byte[] nonce)
              throws Exception {
            throw new IllegalBlockSizeException("");
          }
        });

    subject.matchesCanary(mock(EncryptionKeyCanary.class));
  }

  @Test(expected = IncorrectKeyException.class)
  public void isMatchingCanary_whenDecryptThrowsOtherException_throwsIncorrectKeyException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
        new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
          @Override
          public String decrypt(Key key, byte[] encryptedValue, byte[] nonce)
              throws Exception {
            throw new Exception("");
          }
        });

    subject.matchesCanary(mock(EncryptionKeyCanary.class));
  }
}
