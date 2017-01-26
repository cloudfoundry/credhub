package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@SuppressWarnings("unused")
@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dsm")
public class DyadicEncryptionService extends EncryptionService {
  private final DyadicConnection dyadicConnection;

  private SecureRandom secureRandom;

  @Autowired
  DyadicEncryptionService(DyadicConnection dyadicConnection, EncryptionKeyCanaryMapper keyMapper) throws Exception {
    this.dyadicConnection = dyadicConnection;
    this.secureRandom = new SecureRandom();

    keyMapper.mapUuidsToKeys(this);
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    final String ccmCipherName = CipherTypes.CCM.toString();
    final Provider dyadicConnectionProvider = dyadicConnection.getProvider();

    return new CipherWrapper(Cipher.getInstance(ccmCipherName, dyadicConnectionProvider));
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
