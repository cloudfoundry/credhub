package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;

import java.util.Objects;

class SecretEncryptionHelper {

  void refreshEncryptedValue(EncryptedValueContainer encryptedValueContainer, String clearTextValue) {
    if (clearTextValue == null) {
      encryptedValueContainer.setNonce(null);
      encryptedValueContainer.setEncryptedValue(null);
      return;
    }
    final EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
    try {
      if (encryptedValueContainer.getNonce() == null || encryptedValueContainer.getEncryptedValue() == null || !Objects.equals(clearTextValue, encryptionService.decrypt(encryptedValueContainer.getNonce(), encryptedValueContainer.getEncryptedValue()))) {
        final EncryptionService.Encryption encryption = encryptionService.encrypt(clearTextValue);
        encryptedValueContainer.setNonce(encryption.nonce);
        encryptedValueContainer.setEncryptedValue(encryption.encryptedValue);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  String retrieveClearTextValue(EncryptedValueContainer encryptedValueContainer) {
    if (encryptedValueContainer.getNonce() == null || encryptedValueContainer.getEncryptedValue() == null) {return null;}
    final EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
    try {
      return encryptionService.decrypt(encryptedValueContainer.getNonce(), encryptedValueContainer.getEncryptedValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
