package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.Provider;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class EncryptionServiceImplTest {

  private final String plaintext = "this is a string";

  @Autowired
  @InjectMocks
  EncryptionServiceImpl subject;

  @Mock
  Provider provider;

  private EncryptionService.Encryption encryption;

  {
    beforeEach(() -> {
      subject = new EncryptionServiceImpl(new BCEncryptionConfiguration());
      encryption = subject.encrypt(plaintext);
    });

    it("can encrypt values", () -> {
      assertThat(encryption.nonce, notNullValue());
      assertThat(encryption.encryptedValue, not(equalTo(plaintext)));
    });

    it("can decrypt values", () -> {
      assertThat(subject.decrypt(encryption.nonce, encryption.encryptedValue), equalTo(plaintext));
    });

    it("does not reuse nonces", () -> {
      assertThat(subject.encrypt(plaintext).nonce, not(equalTo(encryption.nonce)));
    });
  }
}