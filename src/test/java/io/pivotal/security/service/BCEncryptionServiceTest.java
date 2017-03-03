package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.junit.runner.RunWith;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class BCEncryptionServiceTest {
  private final String plaintext = "this is a string";
  private BCEncryptionService subject;
  private Encryption encryption;
  private Key encryptionKey;
  private EncryptionKeyCanary canary;

  {
    beforeEach(() -> {
      subject = new BCEncryptionService();

      EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
      keyMetadata.setDevKey("0123456789ABCDEF0123456789ABCDEF");

      encryptionKey = subject.createKeyProxy(keyMetadata).getKey();
    });

    describe("#createKey", () -> {
      describe("#getActiveKey", () -> {
        it("should use the correct algorithm", () -> {
          assertThat(encryptionKey.getAlgorithm(), equalTo("AES"));
        });

        it("should use key of length 128 bits", () -> {
          assertThat(encryptionKey.getEncoded().length, equalTo(16));
        });

        it("should create a key using the provided dev key value", () -> {
          assertThat(DatatypeConverter.printHexBinary(encryptionKey.getEncoded()), equalTo("0123456789ABCDEF0123456789ABCDEF"));
        });
      });
    });

    describe("encryption and decryption", () -> {
      beforeEach(() -> {
        encryption = subject.encrypt(encryptionKey, plaintext);
      });

      it("can encrypt values", () -> {
        assertThat(encryption.nonce, notNullValue());
        assertThat(encryption.encryptedValue, not(CoreMatchers.equalTo(plaintext)));
      });

      it("can decrypt values", () -> {
        assertThat(subject.decrypt(encryptionKey, encryption.encryptedValue, encryption.nonce), CoreMatchers.equalTo(plaintext));
      });

      it("does not reuse nonces", () -> {
        assertThat(subject.encrypt(encryptionKey, plaintext).nonce, not(CoreMatchers.equalTo(encryption.nonce)));
      });
    });

    describe("#isMatchingCanary", () -> {
      describe("happy path", () -> {
        beforeEach(() -> {
          canary = new EncryptionKeyCanary();
          Encryption encryptionData = subject.encrypt(encryptionKey, CANARY_VALUE);
          canary.setEncryptedValue(encryptionData.encryptedValue);
          canary.setNonce(encryptionData.nonce);
        });

        it("finds the canary", () -> {
          assertThat(subject.isMatchingCanary(encryptionKey,canary), equalTo(true));
        });
      });

      describe("when decrypt throws IllegalBlockSizeException containing \"returns 0x40\" message", () -> {
        beforeEach(() -> {
          subject = new BCEncryptionService() {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new IllegalBlockSizeException("returns 0x40");
            }
          };
        });

        it("returns false" , () -> {
          assertThat(subject.isMatchingCanary(mock(KeyProxy.class), mock(EncryptionKeyCanary.class)), equalTo(false));
        });
      });
      describe("when decrypt throws BadPaddingException containing \"rv=48\" message", () -> {
        beforeEach(() -> {
          subject = new BCEncryptionService() {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new BadPaddingException("rv=48");
            }
          };
        });

        it("returns false" , () -> {
          assertThat(subject.isMatchingCanary(mock(KeyProxy.class), mock(EncryptionKeyCanary.class)), equalTo(false));
        });
      });

      describe("when decrypt throws AEADBadTagException", () -> {
        beforeEach(() -> {
          subject = new BCEncryptionService() {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new AEADBadTagException();
            }
          };
        });

        it("returns false" , () -> {
          assertThat(subject.isMatchingCanary(mock(KeyProxy.class), mock(EncryptionKeyCanary.class)), equalTo(false));
        });
      });

      describe("when decrypt throws other exceptions", () -> {
        itThrows("RuntimeException for BadPaddingException", RuntimeException.class, () -> {
          subject = new BCEncryptionService() {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new BadPaddingException("");
            }
          };
          subject.isMatchingCanary(mock(KeyProxy.class), mock(EncryptionKeyCanary.class));
        });

        itThrows("RuntimeException for IllegalBlockSizeException", RuntimeException.class, () -> {
          subject = new BCEncryptionService() {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new IllegalBlockSizeException("");
            }
          };
          subject.isMatchingCanary(mock(KeyProxy.class), mock(EncryptionKeyCanary.class));
        });
        itThrows("RuntimeException for Exception", RuntimeException.class, () -> {
          subject = new BCEncryptionService() {
            @Override
            public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
              throw new Exception("");
            }
          };
          subject.isMatchingCanary(mock(KeyProxy.class), mock(EncryptionKeyCanary.class));
        });
      });
    });

    describe("deriveKey from fixed salt and password", () -> {
      it("returns the expected Key", () -> {
        KeyProxy proxy = new KeyProxy("abcdefghijklmnopqrst");
        byte[] salt =  Hex.decode("7034522dc85138530e44b38d0569ca67"); // gen'd originally from SecureRandom..
        String hexOutput = Hex.toHexString(proxy.getKey(salt).getEncoded());

        assertThat(hexOutput, equalTo("23e48f2bafa327a174a46400063cd9e6"));

      });
    });
  }
}
