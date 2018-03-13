package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionConfiguration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;


class LunaConnection {

  private final EncryptionConfiguration lunaProviderConfiguration;
  private Provider provider;
  private Object lunaSlotManager;
  private KeyStore keyStore;
  private SecureRandom secureRandom;
  private KeyGenerator aesKeyGenerator;


  public LunaConnection(EncryptionConfiguration lunaProviderConfiguration) throws Exception {
    this.lunaProviderConfiguration = lunaProviderConfiguration;
    provider = (Provider) Class.forName("com.safenetinc.luna.provider.LunaProvider").newInstance();
    Security.addProvider(provider);
    lunaSlotManager = Class.forName("com.safenetinc.luna.LunaSlotManager")
        .getDeclaredMethod("getInstance").invoke(null);

    reconnect();

    // https://www.pivotaltracker.com/story/show/148107855
    // SecureRandom seed is 440 bits in accordance with NIST Special Publication 800-90A Revision 1, section 10.1
    // http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
    SecureRandom lunaRandom = SecureRandom.getInstance("LunaRNG");
    secureRandom = SecureRandom.getInstance("SHA1PRNG");
    byte[] seed = lunaRandom.generateSeed(55);
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

  public SecretKey generateKey() {
    return aesKeyGenerator.generateKey();
  }

  private void makeKeyStore() throws Exception {
    keyStore = KeyStore.getInstance("Luna", provider);
    keyStore.load(null, null);
  }

  private void login(String partitionName, String partitionPassword) {
    try {
      lunaSlotManager.getClass().getMethod("login", String.class, String.class)
          .invoke(lunaSlotManager, partitionName, partitionPassword);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void reinitialize() {
    try {
      lunaSlotManager.getClass().getMethod("reinitialize").invoke(lunaSlotManager);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private boolean isLoggedIn() {
    try {
      return (boolean) lunaSlotManager.getClass().getMethod("isLoggedIn").invoke(lunaSlotManager);
    } catch (IllegalAccessException | NoSuchMethodException e) {
      throw new RuntimeException(e);
    } catch (Exception e) {
      return false;
    }
  }

  public boolean containsAlias(String encryptionKeyAlias) throws KeyStoreException {
    return keyStore.containsAlias(encryptionKeyAlias);
  }

  public void setKeyEntry(String encryptionKeyAlias, SecretKey aesKey) throws KeyStoreException {
    keyStore.setKeyEntry(encryptionKeyAlias, aesKey, null , null);
  }

  public Key getKey(String encryptionKeyAlias)
      throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    return keyStore.getKey(encryptionKeyAlias, null);
  }
}
