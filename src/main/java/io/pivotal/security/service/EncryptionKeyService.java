package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.UUID;

@Service
public class EncryptionKeyService {
  public static final Charset CHARSET = Charset.defaultCharset();
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionKeyService(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
  }

  public Key getEncryptionKey(UUID encryptionKeyCanaryUuid) {
    return encryptionKeyCanaryMapper.getEncryptionKeyMap().get(encryptionKeyCanaryUuid);
  }

  public UUID getActiveEncryptionKeyUuid() {
    return encryptionKeyCanaryMapper.getActiveUuid();
  }

  public Key getActiveEncryptionKey() {
    return encryptionKeyCanaryMapper.getEncryptionKeyMap().get(getActiveEncryptionKeyUuid());
  }
}
