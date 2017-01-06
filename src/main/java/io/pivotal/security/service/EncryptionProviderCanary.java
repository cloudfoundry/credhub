package io.pivotal.security.service;

import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import javax.annotation.PostConstruct;

@Component
public class EncryptionProviderCanary {

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  EncryptionConfiguration encryptionConfiguration;

  @Autowired
  EncryptionKeyCanaryDataService birdCage;

  @PostConstruct
  public void checkForDataCorruption() {
    String canaryValue = new String(new byte[128], encryptionService.charset());

    EncryptionKeyCanary canary = birdCage.getOne();
    if (canary == null) {
      canary = new EncryptionKeyCanary();
      try {
        EncryptionService.Encryption encryptedCanary = encryptionService.encrypt(canaryValue);
        canary.setName("canary");
        canary.setEncryptedValue(encryptedCanary.encryptedValue);
        canary.setNonce(encryptedCanary.nonce);
        birdCage.save(canary);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    } else {
      String decryptedResult;
      try {
        decryptedResult = encryptionService.decrypt(canary.getNonce(), canary.getEncryptedValue());
      } catch (Exception e) {
        throw new RuntimeException("Encryption key is mismatched with database. Please check your configuration.");
      }
      if (!canaryValue.equals(decryptedResult)) {
        throw new RuntimeException(
            "Canary value is incorrect. Database has been tampered with. Expected\n" +
                printHexBinary(canaryValue.getBytes()) + " but was\n" +
                printHexBinary(decryptedResult.getBytes())
        );
      }
    }
  }
}
