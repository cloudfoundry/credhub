package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.UUID;

// todo: GROT. Replace with the EncryptionKeyCanaryMapper
@Service
public class EncryptionKeyService {
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionKeyService(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
  }

  public Key getEncryptionKey(UUID encryptionKeyCanaryUuid) {
    return encryptionKeyCanaryMapper.getKeyForUuid(encryptionKeyCanaryUuid);
  }

  public UUID getActiveEncryptionKeyUuid() {
    return encryptionKeyCanaryMapper.getActiveUuid();
  }

  public Key getActiveEncryptionKey() {
    return encryptionKeyCanaryMapper.getActiveKey();
  }
}
