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

  public Encryption encrypt(Key key, String value) throws Exception {
    preventReconnect();

    try {
      return encryptionService.encrypt(key, value);
    } catch (IllegalBlockSizeException | ProviderException e) {
      logger.info("Failed to encrypt secret. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());

      allowReconnect();
      UUID keyId = keyMapper.getUuidForKey(key);
      try {
        reconnectAndRemapKeysToUuids(e);
        logger.info("Reconnected to the HSM");
      } finally {
        preventReconnect();
      }

      return encryptionService.encrypt(keyMapper.getKeyForUuid(keyId), value);
    } finally {
      allowReconnect();
    }
  }

  public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
    preventReconnect();
    try {
      return encryptionService.decrypt(key, encryptedValue, nonce);
    } catch (IllegalBlockSizeException | ProviderException e) {
      logger.info("Failed to decrypt secret. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());

      allowReconnect();
      UUID keyId = keyMapper.getUuidForKey(key);
      try {
        reconnectAndRemapKeysToUuids(e);
        logger.info("Reconnected to the HSM");
      } finally {
        preventReconnect();
      }

      return encryptionService.decrypt(keyMapper.getKeyForUuid(keyId), encryptedValue, nonce);
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
}
