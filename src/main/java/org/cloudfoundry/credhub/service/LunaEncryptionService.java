package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.constants.CipherTypes;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@SuppressWarnings("unused")
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
@Component
public class LunaEncryptionService extends EncryptionService {

  public static final int KEY_POPULATION_WAIT_SEC = 60 *10; // ten minutes
  private final LunaConnection lunaConnection;
  private boolean keyCreationEnabled;
  private TimedRetry timedRetry;
  private final Logger logger;


  @Autowired
  public LunaEncryptionService(
      LunaConnection lunaConnection,
      @Value("${encryption.key_creation_enabled}")
          boolean keyCreationEnabled,
      TimedRetry timedRetry) {
    this.lunaConnection = lunaConnection;
    this.keyCreationEnabled = keyCreationEnabled;
    this.timedRetry = timedRetry;

    logger = LogManager.getLogger();
  }

  @Override
  public SecureRandom getSecureRandom() {
    return lunaConnection.getSecureRandom();
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(
        Cipher.getInstance(CipherTypes.GCM.toString(), lunaConnection.getProvider()));
  }

  @Override
  AlgorithmParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    return new DefaultKeyProxy(createKey(encryptionKeyMetadata, lunaConnection), this);
  }

  private Key createKey(EncryptionKeyMetadata encryptionKeyMetadata,
      LunaConnection connection) {
    try {
      String encryptionKeyName = encryptionKeyMetadata.getEncryptionKeyName();

      if (!connection.containsAlias(encryptionKeyName)) {
        if (keyCreationEnabled) {
          SecretKey aesKey = connection.generateKey();
          logger.info("Not waiting, creating key.");
          connection.setKeyEntry(encryptionKeyName, aesKey);
        } else {
          timedRetry.retryEverySecondUntil(KEY_POPULATION_WAIT_SEC, () -> {
            try {
              logger.info("waiting for another process to create the key");
              return lunaConnection.containsAlias(encryptionKeyName);
            } catch (KeyStoreException e) {
              return false;
            }
          });
        }
      }

      return connection.getKey(encryptionKeyName);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
