package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import org.hamcrest.CoreMatchers;
import org.junit.runner.RunWith;

import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class BCEncryptionServiceTest {
  private final String plaintext = "this is a string";
  private BCEncryptionService subject;
  private Encryption encryption;
  private Key encryptionKey;

  private UUID canaryUuid;

  {
    describe("with a non-null dev key", () -> {
      beforeEach(() -> {
        subject = new BCEncryptionService(getBouncyCastleProvider());
        canaryUuid = UUID.randomUUID();

        EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
        keyMetadata.setDevKey("0123456789ABCDEF0123456789ABCDEF");

        final KeyProxy keyProxy = subject.createKeyProxy(keyMetadata);
        assertThat(keyProxy, instanceOf(DefaultKeyProxy.class));
        encryptionKey = keyProxy.getKey();
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
          encryption = subject.encrypt(canaryUuid, encryptionKey, plaintext);
        });

        it("can encrypt values", () -> {
          assertThat(encryption.nonce, notNullValue());
          assertThat(encryption.encryptedValue, not(CoreMatchers.equalTo(plaintext)));
          assertThat(encryption.canaryUuid, equalTo(canaryUuid));
        });

        it("can decrypt values", () -> {
          assertThat(subject.decrypt(encryptionKey, encryption.encryptedValue, encryption.nonce), equalTo(plaintext));
        });

        it("does not reuse nonces", () -> {
          assertThat(subject.encrypt(canaryUuid, encryptionKey, plaintext).nonce, not(equalTo(encryption.nonce)));
        });
      });
    });

    describe("with a null dev key", () -> {
      it("should created a password-based key proxy", () -> {
        subject = new BCEncryptionService(getBouncyCastleProvider());

        EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
        keyMetadata.setEncryptionPassword("foobar");
        keyMetadata.setDevKey(null);

        final KeyProxy keyProxy = subject.createKeyProxy(keyMetadata);
        assertThat(keyProxy, instanceOf(PasswordBasedKeyProxy.class));
      });
    });
  }
}
