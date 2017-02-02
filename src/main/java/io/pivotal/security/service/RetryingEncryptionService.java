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

  public Encryption encrypt(Key encryptionKey, final String value) throws Exception {
    logger.info("Attempting encrypt");
    return (Encryption) retryOnErrorWithRemappedKey(encryptionKey, key -> encryptionService.encrypt(key, value));
  }

  public String decrypt(Key decryptionKey, final byte[] encryptedValue, final byte[] nonce) throws Exception {
    logger.info("Attempting decrypt");
    return (String) retryOnErrorWithRemappedKey(decryptionKey, key -> encryptionService.decrypt(key, encryptedValue, nonce));
  }

  private <T> T retryOnErrorWithRemappedKey(Key originalKey, ThrowingFunction<Key, T> operation) throws Exception {
    return withPreventReconnectLock(() -> {
      try {
        return operation.apply(originalKey);
      } catch (IllegalBlockSizeException | ProviderException e) {
        logger.info("Operation failed: " + e.getMessage());

        UUID keyId = keyMapper.getUuidForKey(originalKey);

        setNeedsReconnectFlag();
        withPreventCryptoLock(() -> {
          if (needsReconnect()) {
            logger.info("Trying reconnect");
            reconnectAndRemapKeysToUuids(e);
            clearNeedsReconnectFlag();
          }
        });

        return operation.apply(keyMapper.getKeyForUuid(keyId));
      }
    });
  }

  private void reconnectAndRemapKeysToUuids(Exception originalException) throws Exception {
    remoteEncryptionConnectable.reconnect(originalException);
    keyMapper.mapUuidsToKeys();
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
  interface ThrowingFunction<T,R> {
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
