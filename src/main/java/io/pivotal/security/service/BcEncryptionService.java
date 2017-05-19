package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "internal")
public class BcEncryptionService extends EncryptionService {

  private final SecureRandom secureRandom;
  private final Provider bouncyCastleProvider;

  @Autowired
  public BcEncryptionService(BouncyCastleProvider bouncyCastleProvider) throws Exception {
    this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
    this.bouncyCastleProvider = bouncyCastleProvider;
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), bouncyCastleProvider));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), this);
  }
}

