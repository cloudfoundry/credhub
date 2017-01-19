package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.config.LunaProviderProperties;
import io.pivotal.security.constants.CipherTypes;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;

@SuppressWarnings("unused")
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
@Component
public class LunaEncryptionService extends EncryptionService {

  private final LunaProviderProperties lunaProviderProperties;
  private final LunaConnection lunaConnection;
  private Logger logger;

  @Autowired
  public LunaEncryptionService(
      EncryptionKeysConfiguration encryptionKeysConfiguration,
      LunaProviderProperties lunaProviderProperties,
      LunaConnection lunaConnection
  ) {
    this.lunaProviderProperties = lunaProviderProperties;
    this.lunaConnection = lunaConnection;

    logger = LogManager.getLogger();

    login();
    setupKeys(encryptionKeysConfiguration);
  }

  @Override
  public Encryption encrypt(Key key, String value) throws Exception {
    try {
      return super.encrypt(key, value);
    } catch (ProviderException e) {
      logger.info("Failed to encrypt secret. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());
      login();
      logger.info("Reconnected to the HSM");
      return super.encrypt(key, value);
    }
  }

  @Override
  public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
    try {
      return super.decrypt(key, encryptedValue, nonce);
    } catch(IllegalBlockSizeException e) {
      logger.info("Failed to decrypt secret. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());
      login();
      logger.info("Reconnected to the HSM");
      return super.decrypt(key, encryptedValue, nonce);
    }
  }

  @Override
  SecureRandom getSecureRandom() {
    return lunaConnection.getSecureRandom();
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), lunaConnection.getProvider()));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  Key createKey(EncryptionKeyMetadata encryptionKeyMetadata) {
    try {
      KeyStore keyStore = lunaConnection.getKeyStore();
      String encryptionKeyName = encryptionKeyMetadata.getEncryptionKeyName();

      if (!keyStore.containsAlias(encryptionKeyName)) {
        SecretKey aesKey = lunaConnection.getKeyGenerator().generateKey();
        keyStore.setKeyEntry(encryptionKeyName, aesKey, null, null);
      }

      return keyStore.getKey(encryptionKeyName, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void login() {
    lunaConnection.connect(lunaProviderProperties.getPartitionName(), lunaProviderProperties.getPartitionPassword());
  }
}
