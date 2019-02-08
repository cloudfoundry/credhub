package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.beans.factory.annotation.Value;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.constants.CipherTypes;
import org.cloudfoundry.credhub.util.TimedRetry;

public class LunaEncryptionService extends InternalEncryptionService {

  public static final int KEY_POPULATION_WAIT_SEC = 60 * 10; // ten minutes
  private static final Logger LOGGER = LogManager.getLogger();
  private final LunaConnection lunaConnection;
  private final boolean keyCreationEnabled;
  private final TimedRetry timedRetry;

  public LunaEncryptionService(
    final LunaConnection lunaConnection,
    @Value("${encryption.key_creation_enabled}") final
    boolean keyCreationEnabled,
    final TimedRetry timedRetry
  ) {
    super();
    this.lunaConnection = lunaConnection;
    this.keyCreationEnabled = keyCreationEnabled;
    this.timedRetry = timedRetry;
  }

  @Override
  public SecureRandom getSecureRandom() {
    return lunaConnection.getSecureRandom();
  }

  @Override
  public CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(
      Cipher.getInstance(CipherTypes.GCM.toString(), lunaConnection.getProvider()));
  }

  @Override
  public AlgorithmParameterSpec generateParameterSpec(final byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  public KeyProxy createKeyProxy(final EncryptionKeyMetadata encryptionKeyMetadata) {
    return new LunaKeyProxy(createKey(encryptionKeyMetadata, lunaConnection), this);
  }

  private Key createKey(final EncryptionKeyMetadata encryptionKeyMetadata,
                        final LunaConnection connection) {
    try {
      final String encryptionKeyName = encryptionKeyMetadata.getEncryptionKeyName();

      if (!connection.containsAlias(encryptionKeyName)) {
        if (keyCreationEnabled) {
          final SecretKey aesKey = connection.generateKey();
          LOGGER.info("Not waiting, creating key.");
          connection.setKeyEntry(encryptionKeyName, aesKey);
        } else {
          timedRetry.retryEverySecondUntil(KEY_POPULATION_WAIT_SEC, () -> {
            try {
              LOGGER.info("waiting for another process to create the key");
              return lunaConnection.containsAlias(encryptionKeyName);
            } catch (final KeyStoreException e) {
              return false;
            }
          });
        }
      }

      return connection.getKey(encryptionKeyName);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public synchronized void reconnect(final Exception reasonForReconnect) {
    lunaConnection.reconnect();
  }
}
