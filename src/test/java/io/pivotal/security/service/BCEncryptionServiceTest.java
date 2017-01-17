package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.runner.RunWith;

import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class BCEncryptionServiceTest {
  private final String plaintext = "this is a string";
  private BCEncryptionService subject;
  private Encryption encryption;
  private Key activeKey;

  {
    beforeEach(() -> {
      EncryptionKeyMetadata activeDevKey = new EncryptionKeyMetadata();
      activeDevKey.setDevKey("0123456789ABCDEF0123456789ABCDEF");
      activeDevKey.setActive(true);

      EncryptionKeyMetadata inactiveDevKey = new EncryptionKeyMetadata();
      inactiveDevKey.setDevKey("5555556789ABCDEF0123456789ABCDEF");

      EncryptionKeysConfiguration encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);
      when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeDevKey, inactiveDevKey));
      subject = new BCEncryptionService(new BouncyCastleProvider(), encryptionKeysConfiguration);
    });

    describe("#getActiveKey", () -> {
      it("should use the correct algorithm", () -> {
        assertThat(subject.getActiveKey().getAlgorithm(), equalTo("AES"));
      });

      it("should use key of length 128 bits", () -> {
        assertThat(subject.getActiveKey().getEncoded().length, equalTo(16));
      });

      it("should create a key using the provided dev key value", () -> {
        assertThat(DatatypeConverter.printHexBinary(subject.getActiveKey().getEncoded()), equalTo("0123456789ABCDEF0123456789ABCDEF"));
      });
    });

    describe("#getKeys", () -> {
      it("should return the keys", () -> {
        List<String> plaintextKeys = subject.getKeys().stream().map(key -> DatatypeConverter.printHexBinary(key.getEncoded())).collect(Collectors.toList());
        assertThat(plaintextKeys, containsInAnyOrder("0123456789ABCDEF0123456789ABCDEF", "5555556789ABCDEF0123456789ABCDEF"));
      });

      it("should contain a reference to the active key", () -> {
        assertThat(subject.getKeys(), hasItem(subject.getActiveKey()));
      });
    });

    describe("encryption and decryption", () -> {
      {
        beforeEach(() -> {
          activeKey = subject.getActiveKey();

          encryption = subject.encrypt(activeKey, plaintext);
        });

        it("can encrypt values", () -> {
          Assert.assertThat(encryption.nonce, notNullValue());
          Assert.assertThat(encryption.encryptedValue, not(CoreMatchers.equalTo(plaintext)));
        });

        it("can decrypt values", () -> {
          Assert.assertThat(subject.decrypt(activeKey, encryption.encryptedValue, encryption.nonce), CoreMatchers.equalTo(plaintext));
        });

        it("does not reuse nonces", () -> {
          Assert.assertThat(subject.encrypt(activeKey, plaintext).nonce, not(CoreMatchers.equalTo(encryption.nonce)));
        });
      }
    });
  }
}
