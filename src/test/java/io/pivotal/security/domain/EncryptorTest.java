package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.service.BcEncryptionService;
import io.pivotal.security.service.BcNullConnection;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import org.junit.runner.RunWith;

import java.security.Key;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptorTest {

  private EncryptionKeyCanaryMapper keyMapper;
  private Encryptor subject;

  private byte[] encryptedValue;

  private byte[] nonce;
  private UUID oldUuid;
  private UUID newUuid;

  {
    describe("Encryptor", () -> {
      beforeEach(() -> {
        oldUuid = UUID.randomUUID();
        newUuid = UUID.randomUUID();

        keyMapper = mock(EncryptionKeyCanaryMapper.class);
        BcEncryptionService bcEncryptionService;
        bcEncryptionService = new BcEncryptionService(getBouncyCastleProvider());

        Key newKey = new SecretKeySpec(parseHexBinary("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), 0, 16,
            "AES");
        when(keyMapper.getActiveKey()).thenReturn(newKey);
        when(keyMapper.getActiveUuid()).thenReturn(newUuid);
        Key oldKey = new SecretKeySpec(parseHexBinary("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0, 16,
            "AES");
        when(keyMapper.getKeyForUuid(oldUuid)).thenReturn(oldKey);
        when(keyMapper.getKeyForUuid(newUuid)).thenReturn(newKey);

        RetryingEncryptionService encryptionService = new RetryingEncryptionService(
            bcEncryptionService, keyMapper, new BcNullConnection());
        subject = new Encryptor(encryptionService);
      });

      describe("#encrypt", () -> {
        it("should return null values for null input", () -> {
          Encryption encryption = subject.encrypt(null);

          assertThat(encryption.encryptedValue, nullValue());
          assertThat(encryption.nonce, nullValue());
        });

        it("should encrypt plain text", () -> {
          Encryption encryption = subject.encrypt("some value");

          assertThat(encryption.encryptedValue, notNullValue());
          assertThat(encryption.nonce, notNullValue());
        });

        itThrows("should wrap exceptions", RuntimeException.class, () -> {
          when(keyMapper.getActiveUuid()).thenThrow(new IllegalArgumentException());
          subject.encrypt("some value");
        });

      });

      describe("#decrypt", () -> {
        beforeEach(() -> {
          Encryption encryption = subject.encrypt("the expected clear text");
          encryptedValue = encryption.encryptedValue;
          nonce = encryption.nonce;
        });

        it("decrypts things that have been encrypted", () -> {
          assertThat(subject.decrypt(new Encryption(newUuid, encryptedValue, nonce)),
              equalTo("the expected clear text"));
        });

        itThrows("fails to encrypt when given the wrong key UUID", RuntimeException.class, () -> {
          subject.decrypt(new Encryption(oldUuid, encryptedValue, nonce));
        });

      });
    });

  }
}
