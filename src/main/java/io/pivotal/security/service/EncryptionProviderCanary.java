package io.pivotal.security.service;

import io.pivotal.security.data.CanaryDataService;
import io.pivotal.security.entity.NamedCanary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
public class EncryptionProviderCanary {

  static final String CANARY_NAME = "canary";

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  EncryptionConfiguration encryptionConfiguration;

  @Autowired
  CanaryDataService birdCage;

  @PostConstruct
  public void checkForDataCorruption() {
    String canaryValue = new String(new byte[encryptionConfiguration.getKey().getEncoded().length * 8], encryptionService.charset());

    NamedCanary canary = birdCage.findOneByName(CANARY_NAME);
    if (canary == null) {
      canary = new NamedCanary(CANARY_NAME);
      try {
        EncryptionService.Encryption encryptedCanary = encryptionService.encrypt(canaryValue);
        canary.setEncryptedValue(encryptedCanary.encryptedValue);
        canary.setNonce(encryptedCanary.nonce);
        birdCage.save(canary);
      } catch (Exception e) {
        throw new RuntimeException("Failed to create encryption canary value.");
      }
    } else {
      String decryptedResult;
      try {
        decryptedResult = encryptionService.decrypt(canary.getNonce(), canary.getEncryptedValue());
      } catch (Exception e) {
        throw new RuntimeException("Encryption key is mismatched with database. Please check your configuration.");
      }
      if (!canaryValue.equals(decryptedResult)) {
        throw new RuntimeException("Canary value is incorrect. Database has been tampered with.");
      }
    }
  }
}
