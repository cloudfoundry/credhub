package io.pivotal.security.domain;

import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class Encryptor {

  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final RetryingEncryptionService encryptionService;

  @Autowired
  public Encryptor(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      RetryingEncryptionService encryptionService) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptionService = encryptionService;
  }

  public Encryption encrypt(String clearTextValue) {
    try {
      final UUID activeUuid = encryptionKeyCanaryMapper.getActiveUuid();
      return clearTextValue == null
          ? new Encryption(activeUuid, null, null) :
          encryptionService.encrypt(activeUuid, clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(Encryption encryption) {
    if (encryption.canaryUuid == null || encryption.encryptedValue == null || encryption.nonce == null) {
      return null;
    }
    try {
      return encryptionService.decrypt(encryption.canaryUuid, encryption.encryptedValue, encryption.nonce);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
