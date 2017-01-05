package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.DevKeyProvider;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionServiceTest {

  private final String plaintext = "this is a string";
  private BCEncryptionConfiguration bcEncryptionConfiguration;
  private EncryptionService subject;
  private Encryption encryption;
  private EncryptionKey encryptionKey;

  {
    beforeEach(() -> {
      BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
      String activeKey = "1234abcd1234abcd1234abcd1234abcd";
      DevKeyProvider devKeyProvider = new DevKeyProvider() {
        @Override
        public String getDevKey() {
          return activeKey;
        }
      };
      EncryptionKeysConfiguration encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);
      when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKey));
      bcEncryptionConfiguration = new BCEncryptionConfiguration(bouncyCastleProvider, devKeyProvider, encryptionKeysConfiguration);
      encryptionKey = bcEncryptionConfiguration.getActiveKey();

      subject = new EncryptionService();
      encryption = subject.encrypt(encryptionKey, plaintext);
    });

    it("can encrypt values", () -> {
      assertThat(encryption.nonce, notNullValue());
      assertThat(encryption.encryptedValue, not(equalTo(plaintext)));
    });

    it("can decrypt values", () -> {
      assertThat(subject.decrypt(encryptionKey, encryption.encryptedValue, encryption.nonce), equalTo(plaintext));
    });

    it("does not reuse nonces", () -> {
      assertThat(subject.encrypt(encryptionKey, plaintext).nonce, not(equalTo(encryption.nonce)));
    });
  }
}
