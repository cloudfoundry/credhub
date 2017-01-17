package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.config.LunaProviderProperties;
import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

@SuppressWarnings("unused")
@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dsm")
public class DyadicEncryptionService extends EncryptionService {
  private final LunaProviderProperties lunaProviderProperties;
  private final DyadicConnection dyadicConnection;

  private Provider provider;
  private SecureRandom secureRandom;

  @Autowired
  DyadicEncryptionService(EncryptionKeysConfiguration encryptionKeysConfiguration, LunaProviderProperties lunaProviderProperties, DyadicConnection dyadicConnection) throws Exception {
    this.lunaProviderProperties = lunaProviderProperties;
    this.dyadicConnection = dyadicConnection;
    this.secureRandom = new SecureRandom();

    setupKeys(encryptionKeysConfiguration);
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.CCM.toString(), provider));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return dyadicConnection.generateParameterSpec(nonce);
  }

  @Override
  Key createKey(EncryptionKeyMetadata encryptionKeyMetadata) {
    try {
      KeyStore keyStore = dyadicConnection.getKeyStore();
      String encryptionKeyAlias = encryptionKeyMetadata.getEncryptionKeyName();

      if (!keyStore.containsAlias(encryptionKeyAlias)) {
        SecretKey aesKey = dyadicConnection.getKeyGenerator().generateKey();
        keyStore.setKeyEntry(encryptionKeyAlias, aesKey, null, null);
      }

      return keyStore.getKey(encryptionKeyAlias, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
