package io.pivotal.security.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
class LunaConnection {
  private Provider provider;
  private Object lunaSlotManager;
  private KeyStore keyStore;
  private SecureRandom secureRandom;
  private KeyGenerator aesKeyGenerator;
  private ReentrantReadWriteLock readWriteLock;

  public LunaConnection() throws Exception {
    provider = (Provider) Class.forName("com.safenetinc.luna.provider.LunaProvider").newInstance();
    Security.addProvider(provider);
    lunaSlotManager = Class.forName("com.safenetinc.luna.LunaSlotManager").getDeclaredMethod("getInstance").invoke(null);

    secureRandom = SecureRandom.getInstance("LunaRNG");
    aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
    aesKeyGenerator.init(128);

    readWriteLock = new ReentrantReadWriteLock();
  }

  synchronized void connect(String partitionName, String partitionPassword) {
    if (!isLoggedIn()) {
      try {
        reinitialize();
        login(partitionName, partitionPassword);
        makeKeyStore();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  public Provider getProvider() {
    return provider;
  }

  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  KeyGenerator getKeyGenerator() {
    return aesKeyGenerator;
  }

  KeyStore getKeyStore() {
    return keyStore;
  }

  // Reconnection should be exclusive (analogous to a DB write operation).
  ReentrantReadWriteLock.WriteLock reconnectLock() {
    return readWriteLock.writeLock();
  }

  // Normal HSM usage can happen in parallel (analogous to a DB read operation).
  ReentrantReadWriteLock.ReadLock usageLock() {
    return readWriteLock.readLock();
  }

  private void makeKeyStore() throws Exception {
    keyStore = KeyStore.getInstance("Luna", provider);
    keyStore.load(null, null);
  }

  private void login(String partitionName, String partitionPassword) throws Exception {
    lunaSlotManager.getClass().getMethod("login", String.class, String.class).invoke(lunaSlotManager, partitionName, partitionPassword);
  }

  private void reinitialize() throws Exception {
    lunaSlotManager.getClass().getMethod("reinitialize").invoke(lunaSlotManager);
  }

  private Boolean isLoggedIn() {
    try {
      return (Boolean) lunaSlotManager.getClass().getMethod("isLoggedIn").invoke(lunaSlotManager);
    } catch (Exception e) {
      return false;
    }
  }
}
