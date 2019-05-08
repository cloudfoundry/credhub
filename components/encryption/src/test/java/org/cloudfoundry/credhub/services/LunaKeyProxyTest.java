package org.cloudfoundry.credhub.services;

import java.security.Key;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.exceptions.IncorrectKeyException;
import org.cloudfoundry.credhub.utils.TestPasswordKeyProxyFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE;
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
    final PasswordEncryptionService encryptionService = new PasswordEncryptionService(
      new TestPasswordKeyProxyFactory()
    );
    final EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionPassword("p@ssword");

    encryptionKey = encryptionService.createKeyProxy(keyMetadata).getKey();
    canary = new EncryptionKeyCanary();
    final EncryptedValue encryptionData = encryptionService.encrypt(null, encryptionKey, CANARY_VALUE);
    canary.setEncryptedCanaryValue(encryptionData.getEncryptedValue());
    canary.setNonce(encryptionData.getNonce());

    deprecatedCanary = new EncryptionKeyCanary();
    final EncryptedValue deprecatedEncryptionData = encryptionService
      .encrypt(null, encryptionKey, DEPRECATED_CANARY_VALUE);
    deprecatedCanary.setEncryptedCanaryValue(deprecatedEncryptionData.getEncryptedValue());
    deprecatedCanary.setNonce(deprecatedEncryptionData.getNonce());
  }

  @Test
  public void isMatchingCanary_whenCanaryMatches_returnsTrue() throws Exception {
    subject = new LunaKeyProxy(encryptionKey, new PasswordEncryptionService(new TestPasswordKeyProxyFactory()));

    assertThat(subject.matchesCanary(canary), equalTo(true));
  }

  @Test
  public void isMatchingCanary_usingOldCanaryValue_returnsTrue() throws Exception {
    subject = new LunaKeyProxy(encryptionKey, new PasswordEncryptionService(new TestPasswordKeyProxyFactory()));

    assertThat(subject.matchesCanary(deprecatedCanary), equalTo(true));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsRelevantIllegalBlockSizeException_returnsFalse() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new TestPasswordKeyProxyFactory()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce)
          throws Exception {
          throw new IllegalBlockSizeException("returns 0x40");
        }
      });

    assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsAEADBadTagException_returnsFalse() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new TestPasswordKeyProxyFactory()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce)
          throws Exception {
          throw new AEADBadTagException();
        }
      });

    assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
  }

  @Test(expected = IncorrectKeyException.class)
  public void isMatchingCanary_whenDecryptThrowsBadPaddingException_throwsIncorrectKeyException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new TestPasswordKeyProxyFactory()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce)
          throws Exception {
          throw new BadPaddingException("");
        }
      });

    subject.matchesCanary(mock(EncryptionKeyCanary.class));
  }

  @Test(expected = IncorrectKeyException.class)
  public void isMatchingCanary_whenDecryptThrowsIllegalBlockSizeException_throwsIncorrectKeyException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new TestPasswordKeyProxyFactory()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce)
          throws Exception {
          throw new IllegalBlockSizeException("");
        }
      });

    subject.matchesCanary(mock(EncryptionKeyCanary.class));
  }

  @Test(expected = IncorrectKeyException.class)
  public void isMatchingCanary_whenDecryptThrowsOtherException_throwsIncorrectKeyException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new TestPasswordKeyProxyFactory()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce)
          throws Exception {
          throw new Exception("");
        }
      });

    subject.matchesCanary(mock(EncryptionKeyCanary.class));
  }

}
