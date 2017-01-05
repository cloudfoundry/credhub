package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.DevKeyProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class EncryptionServiceTest {

  private final String plaintext = "this is a string";

  BCEncryptionConfiguration bcEncryptionConfiguration;
  EncryptionService subject;

  private Encryption encryption;

  {
    beforeEach(() -> {
      bcEncryptionConfiguration = new BCEncryptionConfiguration();
      bcEncryptionConfiguration.provider = new BouncyCastleProvider();
      bcEncryptionConfiguration.devKeyProvider = new DevKeyProvider() {
        @Override
        public String getDevKey() {
          return "1234abcd1234abcd1234abcd1234abcd";
        }
      };
      bcEncryptionConfiguration.postConstruct();

      subject = new EncryptionService(bcEncryptionConfiguration);
      encryption = subject.encrypt(plaintext);
    });

    it("can encrypt values", () -> {
      assertThat(encryption.nonce, notNullValue());
      assertThat(encryption.encryptedValue, not(equalTo(plaintext)));
    });

    it("can decrypt values", () -> {
      assertThat(subject.decrypt(encryption.encryptedValue, encryption.nonce), equalTo(plaintext));
    });

    it("does not reuse nonces", () -> {
      assertThat(subject.encrypt(plaintext).nonce, not(equalTo(encryption.nonce)));
    });
  }
}
