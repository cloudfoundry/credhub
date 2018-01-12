package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.RetryingEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class Encryptor {

  private final RetryingEncryptionService encryptionService;

  @Autowired
  public Encryptor(RetryingEncryptionService encryptionService) {
    this.encryptionService = encryptionService;
  }

  public EncryptedValue encrypt(String clearTextValue) {
    if (clearTextValue == null) {
      return new EncryptedValue();
    }
    try {
      return encryptionService.encrypt(clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(EncryptedValue encryption) {
    if (encryption == null ||
        encryption.getEncryptionKeyUuid() == null ||
        encryption.getEncryptedValue() == null ||
        encryption.getNonce() == null) {
      return null;
    }
    try {
      return encryptionService.decrypt(encryption);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
