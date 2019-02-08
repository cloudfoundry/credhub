package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.cloudfoundry.credhub.config.EncryptionConfiguration;

public class LunaConnection {

  private final EncryptionConfiguration lunaProviderConfiguration;
  private final Provider provider;
  private final Object lunaSlotManager;
  private KeyStore keyStore;
  private final SecureRandom secureRandom;
  private final KeyGenerator aesKeyGenerator;

  public LunaConnection(final EncryptionConfiguration lunaProviderConfiguration) throws Exception {
    super();
    this.lunaProviderConfiguration = lunaProviderConfiguration;
    provider = (Provider) Class.forName("com.safenetinc.luna.provider.LunaProvider").newInstance();
    Security.addProvider(provider);
    lunaSlotManager = Class.forName("com.safenetinc.luna.LunaSlotManager")
      .getDeclaredMethod("getInstance").invoke(null);

    reconnect();

    // https://www.pivotaltracker.com/story/show/148107855
    // SecureRandom seed is 440 bits in accordance with NIST Special Publication 800-90A Revision 1, section 10.1
    // http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
    final SecureRandom lunaRandom = SecureRandom.getInstance("LunaRNG");
    secureRandom = SecureRandom.getInstance("SHA1PRNG");
    final byte[] seed = lunaRandom.generateSeed(55);
    secureRandom.setSeed(seed); // 55b * 8 = 440B

    aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
    aesKeyGenerator.init(128);
  }

  public synchronized void reconnect() {
    if (!isLoggedIn()) {
      try {
        reinitialize();
        login(lunaProviderConfiguration.getPartition(),
          lunaProviderConfiguration.getPartitionPassword());
        makeKeyStore();
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  public Provider getProvider() {
    return provider;
  }

  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  public SecretKey generateKey() {
    return aesKeyGenerator.generateKey();
  }

  public boolean containsAlias(final String encryptionKeyAlias) throws KeyStoreException {
    return keyStore.containsAlias(encryptionKeyAlias);
  }

  public void setKeyEntry(final String encryptionKeyAlias, final SecretKey aesKey) throws KeyStoreException {
    keyStore.setKeyEntry(encryptionKeyAlias, aesKey, null, null);
  }

  public Key getKey(final String encryptionKeyAlias)
    throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return keyStore.getKey(encryptionKeyAlias, null);
  }

  private void makeKeyStore() throws Exception {
    keyStore = KeyStore.getInstance("Luna", provider);
    keyStore.load(null, null);
  }

  private void login(final String partitionName, final String partitionPassword) {
    try {
      lunaSlotManager.getClass().getMethod("login", String.class, String.class)
        .invoke(lunaSlotManager, partitionName, partitionPassword);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void reinitialize() {
    try {
      lunaSlotManager.getClass().getMethod("reinitialize").invoke(lunaSlotManager);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  private boolean isLoggedIn() {
    try {
      return (boolean) lunaSlotManager.getClass().getMethod("isLoggedIn").invoke(lunaSlotManager);
    } catch (final IllegalAccessException | NoSuchMethodException e) {
      throw new RuntimeException(e);
    } catch (final Exception e) {
      return false;
    }
  }
}
