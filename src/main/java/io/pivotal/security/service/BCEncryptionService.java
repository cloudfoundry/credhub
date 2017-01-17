package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionService extends EncryptionService {
  private SecureRandom secureRandom;

  private final BouncyCastleProvider provider;

  @Autowired
  BCEncryptionService(
      BouncyCastleProvider provider,
      EncryptionKeysConfiguration encryptionKeysConfiguration
  ) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    this.provider = provider;

    KeyStore keyStore = KeyStore.getInstance("BKS", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("SHA1PRNG");

    setupKeys(encryptionKeysConfiguration);
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), provider));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  Key createKey(EncryptionKeyMetadata encryptionKeyMetadata) {
    return new SecretKeySpec(DatatypeConverter.parseHexBinary(encryptionKeyMetadata.getDevKey()), 0, 16, "AES");
  }
}
