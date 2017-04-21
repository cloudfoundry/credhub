package io.pivotal.security.domain;

import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.RetryingEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class Encryptor {

  private final RetryingEncryptionService encryptionService;

  @Autowired
  public Encryptor(RetryingEncryptionService encryptionService) {
    this.encryptionService = encryptionService;
  }

  public Encryption encrypt(String clearTextValue) {
    try {
      return clearTextValue == null
          ? new Encryption(null, null, null) :
          encryptionService.encrypt(clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(Encryption encryption) {
    if (encryption.canaryUuid == null || encryption.encryptedValue == null || encryption.nonce == null) {
      return null;
    }
    try {
      return encryptionService.decrypt(encryption);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
