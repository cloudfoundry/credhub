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
  Encryptor(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper, RetryingEncryptionService encryptionService) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptionService = encryptionService;
  }

  public Encryption encrypt(String clearTextValue) {
    try {
      return clearTextValue == null ?
          new Encryption(null, null) :
          encryptionService.encrypt(encryptionKeyCanaryMapper.getActiveUuid(), clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(UUID keyUuid, byte[] encryptedValue, byte[] nonce) {
    if(keyUuid == null || encryptedValue == null || nonce == null) {
      return null;
    }
    try {
      return encryptionService.decrypt(keyUuid, encryptedValue, nonce);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public UUID getActiveUuid() {
    return encryptionKeyCanaryMapper.getActiveUuid();
  }
}
