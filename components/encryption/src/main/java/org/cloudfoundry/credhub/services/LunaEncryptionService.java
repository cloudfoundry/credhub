package org.cloudfoundry.credhub.services;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.constants.CipherTypes;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.util.TimedRetry;

import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CHARSET;

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
  public EncryptedValue encrypt(final UUID canaryUuid, final Key key, final String value) throws Exception {
    final AlgorithmParameterSpec parameterSpec = generateParameterSpec(null);
    final CipherWrapper encryptionCipher = getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

    final byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new EncryptedValue(canaryUuid, encrypted, encryptionCipher.getIV());
  }

  @Override
  public AlgorithmParameterSpec generateParameterSpec(final byte[] iv) {
    AlgorithmParameterSpec algorithmParameterSpec = null;
    try {
      algorithmParameterSpec = (AlgorithmParameterSpec) Class.forName("com.safenetinc.luna.provider.param.LunaGcmParameterSpec")
        .getDeclaredConstructor(byte[].class, byte[].class, int.class)
        .newInstance(iv, "AAD4".getBytes(StandardCharsets.UTF_8), 128);
    } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException | ClassNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
    }
    return algorithmParameterSpec;
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

  public boolean isLoggedIn(){
    return lunaConnection.isLoggedIn();
  }
}
