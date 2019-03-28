package org.cloudfoundry.credhub.services;

import java.security.ProviderException;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.IllegalBlockSizeException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;

@Component
public class RetryingEncryptionService {

  private static final Logger LOGGER = LogManager.getLogger();
  private final EncryptionKeySet keySet;
  private boolean needsReconnect;

  // for testing
  protected ReentrantReadWriteLock readWriteLock;

  @Autowired
  public RetryingEncryptionService(final EncryptionKeySet keySet) {
    super();
    this.keySet = keySet;

    readWriteLock = new ReentrantReadWriteLock();
  }

  public EncryptedValue encrypt(final String value) throws Exception {

    LOGGER.info("Attempting encrypt");
    return retryOnErrorWithRemappedKey(() -> keySet.getActive().encrypt(value));
  }

  public String decrypt(final EncryptedValue encryptedValue)
    throws Exception {
    LOGGER.info("Attempting decrypt");
    return retryOnErrorWithRemappedKey(() -> {
      final EncryptionKey key = keySet.get(encryptedValue.getEncryptionKeyUuid());

      if (key == null) {
        throw new KeyNotFoundException(ErrorMessages.MISSING_ENCRYPTION_KEY);
      }
      return key.decrypt(encryptedValue.getEncryptedValue(), encryptedValue.getNonce());
    });
  }

  // for testing. so sorry
  protected void setNeedsReconnectFlag() {
    needsReconnect = true;
  }

  private <T> T retryOnErrorWithRemappedKey(final ThrowingFunction<T> operation)
    throws Exception {
    return withPreventReconnectLock(() -> {
      try {
        return operation.apply();
      } catch (final IllegalBlockSizeException | ProviderException e) {
        LOGGER.info("Operation failed: " + e.getMessage());

        setNeedsReconnectFlag();
        withPreventCryptoLock(() -> {
          final EncryptionProvider provider = keySet.getActive().getProvider();
          if (needsReconnect && provider instanceof LunaEncryptionService) {
            LOGGER.info("Trying reconnect");
            final LunaEncryptionService lunaEncryptionService = (LunaEncryptionService) provider;
            lunaEncryptionService.reconnect(e);
            keySet.reload();
            clearNeedsReconnectFlag();
          } else if (needsReconnect) {
            throw e;
          }
        });

        return operation.apply();
      }
    });
  }

  private <T> T withPreventReconnectLock(final ThrowingSupplier<T> operation) throws Exception {
    readWriteLock.readLock().lock();
    try {
      return operation.get();
    } finally {
      readWriteLock.readLock().unlock();
    }
  }

  private void withPreventCryptoLock(final ThrowingRunnable runnable) throws Exception {
    readWriteLock.readLock().unlock();
    readWriteLock.writeLock().lock();

    try {
      runnable.run();
    } finally {
      readWriteLock.writeLock().unlock();
      readWriteLock.readLock().lock();
    }
  }

  private void clearNeedsReconnectFlag() {
    needsReconnect = false;
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
