package org.cloudfoundry.credhub.services;

import java.security.Key;

import javax.crypto.AEADBadTagException;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.utils.PasswordKeyProxyFactoryTestImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.assertj.core.api.Java6Assertions.fail;
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
      new PasswordKeyProxyFactoryTestImpl()
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
    subject = new LunaKeyProxy(encryptionKey, new PasswordEncryptionService(new PasswordKeyProxyFactoryTestImpl()));

    assertThat(subject.matchesCanary(canary), equalTo(true));
  }

  @Test
  public void isMatchingCanary_usingOldCanaryValue_returnsTrue() throws Exception {
    subject = new LunaKeyProxy(encryptionKey, new PasswordEncryptionService(new PasswordKeyProxyFactoryTestImpl()));

    assertThat(subject.matchesCanary(deprecatedCanary), equalTo(true));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsAEADBadTagException_returnsFalse() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce)
          throws Exception {
          throw new AEADBadTagException();
        }
      });

    assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsExceptionWithCauseIndicatingTheKeyIsIncorrect_returnsFalse() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce) {
          throw new RuntimeException(new RuntimeException("returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)"));
        }
      });

    assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
  }

  @Test
  public void isMatchingCanary_whenDecryptThrowsExceptionWithOtherCause_throwsRuntimeException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce) {
          throw new RuntimeException(new RuntimeException(("some message that isn't 0x40...")));
        }
      });

    try {
      subject.matchesCanary(mock(EncryptionKeyCanary.class));
      fail("Expected to get RuntimeException");
    } catch (RuntimeException e) {
      assertThat(e.getCause().getCause().getMessage(), equalTo("some message that isn't 0x40..."));
    }
  }


  @Test
  public void isMatchingCanary_WhenDecryptThrowsExceptionWithNoCause_throwsRuntimeException() throws Exception {
    subject = new LunaKeyProxy(encryptionKey,
      new PasswordEncryptionService(new PasswordKeyProxyFactoryTestImpl()) {
        @Override
        public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce) {
          throw new RuntimeException("test message");
        }
      });

    try {
      subject.matchesCanary(mock(EncryptionKeyCanary.class));
      fail("Expected to get RuntimeException");
    } catch (RuntimeException e) {
      assertThat(e.getCause().getMessage(), equalTo("test message"));
    }
  }

//  @Test(expected = RuntimeException.class)
//  public void isMatchingCanary_whenDecryptThrows
}
