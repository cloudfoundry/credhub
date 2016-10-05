package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.security.Provider;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "EncryptionServiceImplTest"})
public class EncryptionServiceImplTest {

  private final String plaintext = "this is a string";

  @Autowired
  BCEncryptionConfiguration bcEncryptionConfiguration;

  @Autowired
  @InjectMocks
  EncryptionServiceImpl subject;

  @Mock
  Provider provider;

  private EncryptionService.Encryption encryption;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new EncryptionServiceImpl(bcEncryptionConfiguration);
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
