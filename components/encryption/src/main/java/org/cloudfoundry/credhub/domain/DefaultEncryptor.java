package org.cloudfoundry.credhub.domain;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.services.RetryingEncryptionService;

import java.util.UUID;

@Component
public class DefaultEncryptor implements Encryptor {

  private final RetryingEncryptionService encryptionService;

  @Autowired
  public DefaultEncryptor(final RetryingEncryptionService encryptionService) {
    super();
    this.encryptionService = encryptionService;
  }

  @Override
  public EncryptedValue encrypt(final String clearTextValue, UUID credentialVersionUUID) {
    if (clearTextValue == null) {
      return new EncryptedValue();
    }
    try {
      return encryptionService.encrypt(clearTextValue, credentialVersionUUID);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
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
