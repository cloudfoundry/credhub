package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import java.security.Key;
import javax.crypto.SecretKey;

public abstract class EncryptionServiceWithConnection extends EncryptionService {

  protected Key createKey(EncryptionKeyMetadata encryptionKeyMetadata,
      LunaConnection connection) {
    try {
      String encryptionKeyAlias = encryptionKeyMetadata.getEncryptionKeyName();

      if (!connection.containsAlias(encryptionKeyAlias)) {
        SecretKey aesKey = connection.generateKey();
        connection.setKeyEntry(encryptionKeyAlias, aesKey);
      }

      return connection.getKey(encryptionKeyAlias);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
