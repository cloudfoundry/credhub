package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.Key;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class DefaultKeyProxyTest {
  private EncryptionService hostEncryptionService;
  private DefaultKeyProxy subject;
  private Key encryptionKey;
  private EncryptionKeyCanary canary;


  {
    beforeEach(() -> {
      final BCEncryptionService encryptionService = new BCEncryptionService(getBouncyCastleProvider());
      EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
      keyMetadata.setDevKey("0123456789ABCDEF0123456789ABCDEF");

      encryptionKey = encryptionService.createKeyProxy(keyMetadata).getKey();
      canary = new EncryptionKeyCanary();
      Encryption encryptionData = encryptionService.encrypt(encryptionKey, CANARY_VALUE);
      canary.setEncryptedValue(encryptionData.encryptedValue);
      canary.setNonce(encryptionData.nonce);
    });

    describe("#isMatchingCanary", () -> {
      beforeEach(() -> {
        subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(new BouncyCastleProvider()));
      });
      describe("happy path", () -> {
        it("finds the canary", () -> {
          assertThat(subject.matchesCanary(canary), equalTo(true));
        });
      });

      describe("when decrypt throws IllegalBlockSizeException containing \"returns 0x40\" message", () -> {
        beforeEach(() -> {
          subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(getBouncyCastleProvider()) {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new IllegalBlockSizeException("returns 0x40");
            }
          });
        });

        it("returns false" , () -> {
          assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
        });
      });
      describe("when decrypt throws BadPaddingException containing \"rv=48\" message", () -> {
        beforeEach(() -> {
          subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(getBouncyCastleProvider()) {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new BadPaddingException("rv=48");
            }
          });
        });

        it("returns false" , () -> {
          assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
        });
      });

      describe("when decrypt throws AEADBadTagException", () -> {
        beforeEach(() -> {
          subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(getBouncyCastleProvider()) {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new AEADBadTagException();
            }
          });
        });

        it("returns false" , () -> {
          assertThat(subject.matchesCanary(mock(EncryptionKeyCanary.class)), equalTo(false));
        });
      });

      describe("when decrypt throws other exceptions", () -> {
        itThrows("RuntimeException for BadPaddingException", RuntimeException.class, () -> {
          subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(getBouncyCastleProvider()) {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new BadPaddingException("");
            }
          });
          subject.matchesCanary(mock(EncryptionKeyCanary.class));
        });

        itThrows("RuntimeException for IllegalBlockSizeException", RuntimeException.class, () -> {
          subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(getBouncyCastleProvider()) {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new IllegalBlockSizeException("");
            }
          });
          subject.matchesCanary(mock(EncryptionKeyCanary.class));
        });
        itThrows("RuntimeException for Exception", RuntimeException.class, () -> {
          subject = new DefaultKeyProxy(encryptionKey, new BCEncryptionService(getBouncyCastleProvider()) {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new Exception("");
            }
          });
          subject.matchesCanary(mock(EncryptionKeyCanary.class));
        });
      });
    });
  }
}
