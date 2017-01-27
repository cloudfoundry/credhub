package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@SuppressWarnings("unused")
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
@Component
public class LunaEncryptionService extends EncryptionService {

  private final LunaConnection lunaConnection;

  @Autowired
  public LunaEncryptionService(LunaConnection lunaConnection) {
    this.lunaConnection = lunaConnection;

    lunaConnection.reconnect(null);
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
}
