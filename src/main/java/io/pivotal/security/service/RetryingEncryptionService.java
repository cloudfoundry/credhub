package io.pivotal.security.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
  private final Logger logger;
  private volatile boolean needsReconnect; // volatile so all threads see changes

  @Autowired
  public RetryingEncryptionService(EncryptionService encryptionService,
                                   EncryptionKeyCanaryMapper keyMapper,
                                   RemoteEncryptionConnectable remoteEncryptionConnectable) {
    this.encryptionService = encryptionService;
    this.keyMapper = keyMapper;
    this.remoteEncryptionConnectable = remoteEncryptionConnectable;

    logger = LogManager.getLogger();
    readWriteLock = new ReentrantReadWriteLock();
  }

  public Encryption encrypt(UUID keyId, final String value) throws Exception {
    logger.info("Attempting encrypt");
    return retryOnErrorWithRemappedKey(keyId, key -> encryptionService.encrypt(key, value));
  }

  public String decrypt(UUID keyId, final byte[] encryptedValue, final byte[] nonce) throws Exception {
    logger.info("Attempting decrypt");
    return retryOnErrorWithRemappedKey(keyId, key -> encryptionService.decrypt(key, encryptedValue, nonce));
  }

  private <T> T retryOnErrorWithRemappedKey(UUID keyId, ThrowingFunction<Key, T> operation) throws Exception {
    return withPreventReconnectLock(() -> {
      try {
        return operation.apply(keyMapper.getKeyForUuid(keyId));
      } catch (IllegalBlockSizeException | ProviderException e) {
        logger.info("Operation failed: " + e.getMessage());

        setNeedsReconnectFlag();
        withPreventCryptoLock(() -> {
          if (needsReconnect()) {
            logger.info("Trying reconnect");
            remoteEncryptionConnectable.reconnect(e);
            keyMapper.mapUuidsToKeys();
            clearNeedsReconnectFlag();
          }
        });

        return operation.apply(keyMapper.getKeyForUuid(keyId));
      }
    });
  }

  private <T> T withPreventReconnectLock(ThrowingSupplier<T> operation) throws Exception {
    readWriteLock.readLock().lock();
    try {
      return operation.get();
    } finally {
      readWriteLock.readLock().unlock();
    }
  }

  private void withPreventCryptoLock(ThrowingRunnable runnable) throws Exception {
    readWriteLock.readLock().unlock();
    readWriteLock.writeLock().lock();

    try {
      runnable.run();
    } finally {
      readWriteLock.writeLock().unlock();
      readWriteLock.readLock().lock();
    }
  }

  // for testing. so sorry
  void setNeedsReconnectFlag() {
    needsReconnect = true;
  }

  private void clearNeedsReconnectFlag() {
    needsReconnect = false;
  }

  private boolean needsReconnect() {
    return needsReconnect;
  }

  @FunctionalInterface
  private interface ThrowingFunction<T, R> {
    R apply(T t) throws Exception;
  }

  @FunctionalInterface
  public interface ThrowingSupplier<T> {
    T get() throws Exception;
  }

  @FunctionalInterface
  public interface ThrowingRunnable {
    void run() throws Exception;
  }
}
