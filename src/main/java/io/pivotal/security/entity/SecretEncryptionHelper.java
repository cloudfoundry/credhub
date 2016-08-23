package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.EncryptionServiceImpl;

import java.util.Objects;

class SecretEncryptionHelper <T extends SecretEncryptor> {

  T encryptPrivateKey(T secretEncrypter, String privateKey) {
    if (Objects.equals(privateKey, secretEncrypter.getCachedItem())) {
      return secretEncrypter;
    }
    if (privateKey == null) {
      secretEncrypter.setCachedItem(null);
      secretEncrypter.setEncryptedValue(null);
      secretEncrypter.setNonce(null);
    } else {
      try {
        EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
        EncryptionServiceImpl.Encryption encryption = encryptionService.encrypt(privateKey);
        secretEncrypter.setCachedItem(privateKey);
        secretEncrypter.setNonce(encryption.nonce);
        secretEncrypter.setEncryptedValue(encryption.encryptedValue);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
    return secretEncrypter;
  }

  String decryptPrivateKey(T secretEncrypter) {
    byte[] encryptedValue = secretEncrypter.getEncryptedValue();
    if (encryptedValue == null) {
      return null;
    }
    try {
      EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
      return encryptionService.decrypt(secretEncrypter.getNonce(), encryptedValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
