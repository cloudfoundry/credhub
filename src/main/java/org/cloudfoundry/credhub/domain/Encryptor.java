package org.cloudfoundry.credhub.domain;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.RetryingEncryptionService;

@Component
public class Encryptor {

  private final RetryingEncryptionService encryptionService;

  @Autowired
  public Encryptor(final RetryingEncryptionService encryptionService) {
    super();
    this.encryptionService = encryptionService;
  }

  public EncryptedValue encrypt(final String clearTextValue) {
    if (clearTextValue == null) {
      return new EncryptedValue();
    }
    try {
      return encryptionService.encrypt(clearTextValue);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(final EncryptedValue encryption) {
    if (encryption == null ||
      encryption.getEncryptionKeyUuid() == null ||
      encryption.getEncryptedValue() == null ||
      encryption.getNonce() == null) {
      return null;
    }
    try {
      return encryptionService.decrypt(encryption);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }
}
