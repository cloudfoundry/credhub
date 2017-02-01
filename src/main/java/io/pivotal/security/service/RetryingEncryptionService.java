package io.pivotal.security.service;

import org.apache.logging.log4j.LogManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.ProviderException;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.IllegalBlockSizeException;

@Component
public class RetryingEncryptionService {
  // for testing
  ReentrantReadWriteLock readWriteLock;
  private final EncryptionService encryptionService;
  private final EncryptionKeyCanaryMapper keyMapper;
  private final RemoteEncryptionConnectable remoteEncryptionConnectable;
  private final org.apache.logging.log4j.Logger logger;

  @Autowired
  public RetryingEncryptionService(EncryptionService encryptionService, EncryptionKeyCanaryMapper keyMapper, RemoteEncryptionConnectable remoteEncryptionConnectable) {
    this.encryptionService = encryptionService;
    this.keyMapper = keyMapper;
    this.remoteEncryptionConnectable = remoteEncryptionConnectable;

    logger = LogManager.getLogger();
    readWriteLock = new ReentrantReadWriteLock();
  }

  public Encryption encrypt(Key encryptionKey, final String value) throws Exception {
    logger.info("Attempting encrypt");
    return (Encryption) retryOnErrorWithRemappedKey(encryptionKey, key -> encryptionService.encrypt(key, value));
  }

  public String decrypt(Key decryptionKey, final byte[] encryptedValue, final byte[] nonce) throws Exception {
    logger.info("Attempting decrypt");
    return (String) retryOnErrorWithRemappedKey(decryptionKey, key -> encryptionService.decrypt(key, encryptedValue, nonce));
  }

  private Object retryOnErrorWithRemappedKey(Key originalKey, ThrowingFunction<Key, Object> operation) throws Exception {
    preventReconnect();

    try {
      return operation.apply(originalKey);
    } catch (IllegalBlockSizeException | ProviderException e) {
      logger.info("Operation failed. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());

      allowReconnect();
      UUID keyId = keyMapper.getUuidForKey(originalKey);
      try {
        reconnectAndRemapKeysToUuids(e);
        logger.info("Reconnected to the HSM");
      } finally {
        preventReconnect();
      }

      return operation.apply(keyMapper.getKeyForUuid(keyId));
    } finally {
      allowReconnect();
    }
  }

  private void reconnectAndRemapKeysToUuids(Exception originalException) throws Exception {
    takeOwnershipForReconnect();
    try {
      remoteEncryptionConnectable.reconnect(originalException);
      keyMapper.mapUuidsToKeys();
    } finally {
      returnOwnershipAfterReconnect();
    }
  }

  private void preventReconnect() {
    readWriteLock.readLock().lock();
  }

  private void allowReconnect() {
    readWriteLock.readLock().unlock();
  }

  private void returnOwnershipAfterReconnect() {
    readWriteLock.writeLock().unlock();
  }

  private void takeOwnershipForReconnect() {
    readWriteLock.writeLock().lock();
  }

  @FunctionalInterface
  interface ThrowingFunction<T,R> {
    R apply(T t) throws Exception;
  }
}
