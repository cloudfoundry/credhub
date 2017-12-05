package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.IllegalBlockSizeException;
import java.security.Key;
import java.security.ProviderException;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Component
public class RetryingEncryptionService {

  private final EncryptionService encryptionService;
  private final EncryptionKeyCanaryMapper keyMapper;
  private final RemoteEncryptionConnectable remoteEncryptionConnectable;
  private final Logger logger;
  // for testing
  ReentrantReadWriteLock readWriteLock;
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

  public EncryptedValue encrypt(final String value) throws Exception {
    logger.info("Attempting encrypt");
    return retryOnErrorWithRemappedKey(() -> encryptionService.encrypt(keyMapper.getActiveUuid(), keyMapper.getActiveKey(), value));
  }

  public String decrypt(EncryptedValue encryptedValue)
      throws Exception {
    logger.info("Attempting decrypt");
    return retryOnErrorWithRemappedKey(() -> {
      final Key key = keyMapper.getKeyForUuid(encryptedValue.getEncryptionKeyUuid());

      if (key == null) {
        throw new KeyNotFoundException("error.missing_encryption_key");
      }

      return encryptionService.decrypt(key, encryptedValue.getEncryptedValue(), encryptedValue.getNonce());
    });
  }

  private <T> T retryOnErrorWithRemappedKey(ThrowingFunction<T> operation)
      throws Exception {
    return withPreventReconnectLock(() -> {
      try {
        return operation.apply();
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

        return operation.apply();
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
  private interface ThrowingFunction<R> {

    R apply() throws Exception;
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
