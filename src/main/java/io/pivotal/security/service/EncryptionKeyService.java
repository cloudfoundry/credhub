package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class EncryptionKeyService {
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionKeyService(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
  }

  public EncryptionKey getEncryptionKey(UUID encryptionKeyCanaryUuid) {
    return encryptionKeyCanaryMapper.getEncryptionKeyMap().get(encryptionKeyCanaryUuid);
  }

  public UUID getActiveEncryptionKeyUuid() {
    return encryptionKeyCanaryMapper.getActiveUuid();
  }

  public EncryptionKey getActiveEncryptionKey() {
    return encryptionKeyCanaryMapper.getEncryptionKeyMap().get(getActiveEncryptionKeyUuid());
  }
}
