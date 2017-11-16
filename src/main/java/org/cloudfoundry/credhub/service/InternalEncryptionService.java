package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "internal")
public class InternalEncryptionService extends EncryptionService {
  public static final int GCM_TAG_LENGTH = 128;

  private final SecureRandom secureRandom;
  private final PasswordKeyProxyFactory passwordKeyProxyFactory;

  @Autowired
  public InternalEncryptionService(PasswordKeyProxyFactory passwordKeyProxyFactory) throws Exception {
    this.passwordKeyProxyFactory = passwordKeyProxyFactory;
    this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
  }

  @Override
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString()));
  }

  @Override
  AlgorithmParameterSpec generateParameterSpec(byte[] nonce) {
    return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
  }

  @Override
  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    return passwordKeyProxyFactory.createPasswordKeyProxy(encryptionKeyMetadata, this);
  }
}

