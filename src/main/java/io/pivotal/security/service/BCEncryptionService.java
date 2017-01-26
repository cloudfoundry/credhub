package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionService extends EncryptionService {
  private SecureRandom secureRandom;

  private final BouncyCastleProvider provider;

  @Autowired
  BCEncryptionService(BouncyCastleProvider provider, EncryptionKeyCanaryMapper keyMapper) throws Exception {
    this.provider = provider;
    this.secureRandom = SecureRandom.getInstance("SHA1PRNG");

    keyMapper.mapUuidsToKeys(this);
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
