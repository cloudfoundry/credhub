package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCanary;
import io.pivotal.security.repository.CanaryRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.service.EncryptionProviderCanary.CANARY_NAME;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class EncryptionProviderCanaryTest {

  @Autowired
  CanaryRepository canaryRepository;

  @Autowired
  EncryptionProviderCanary subject;

  @Autowired
  EncryptionConfiguration encryptionConfiguration;

  private NamedCanary canary;

  {
    wireAndUnwire(this);

    describe("data corruption", () -> {
      beforeEach(() -> {
        assertNull(canaryRepository.findOneByName(CANARY_NAME));

        subject.checkForDataCorruption();
        canary = canaryRepository.findOneByName(CANARY_NAME);
      });

      it("creates a new canary value if one doesn't exist", () -> {
        assertNotNull(canary);
        assertNotNull(canary.getEncryptedValue());
        assertNotNull(canary.getNonce());
      });

      it("doesn't fail if it can decrypt canary value", () -> {
        subject.checkForDataCorruption();

        assertThat(canaryRepository.count(), equalTo(1L));
      });

      itThrowsWithMessage("raises when the canary value is incorrect", RuntimeException.class, "Canary value is incorrect. Database has been tampered with.", () -> {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

        NamedCanary canary = canaryRepository.findOneByName(CANARY_NAME);
        IvParameterSpec ivSpec = new IvParameterSpec(canary.getNonce());
        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding", bouncyCastleProvider);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionConfiguration.getKey(), ivSpec);
        byte[] encrypted = encryptionCipher.doFinal("something else".getBytes());
        canary.setEncryptedValue(encrypted);
        canaryRepository.saveAndFlush(canary);

        subject.checkForDataCorruption();
      });

      itThrowsWithMessage("it cannot decrypt due to a mismatched key", RuntimeException.class, "Encryption key is mismatched with database. Please check your configuration.", () -> {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

        NamedCanary canary = canaryRepository.findOneByName(CANARY_NAME);
        IvParameterSpec ivSpec = new IvParameterSpec(canary.getNonce());
        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding", bouncyCastleProvider);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", bouncyCastleProvider);
        keyGenerator.init(encryptionConfiguration.getKey().getEncoded().length * 8);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, keyGenerator.generateKey(), ivSpec);
        byte[] encrypted = encryptionCipher.doFinal(new byte[100]);
        canary.setEncryptedValue(encrypted);
        canaryRepository.saveAndFlush(canary);

        subject.checkForDataCorruption();
      });
    });
  }
}
