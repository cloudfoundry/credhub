package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptedValue;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public interface EncryptionProvider {

  EncryptedValue encrypt(EncryptionKey key, String value) throws Exception;

  String decrypt(EncryptionKey key, byte[] encryptedValue, byte[] nonce) throws Exception;

  default SecureRandom getSecureRandom(){
    SecureRandom secureRandom = null;

    try {
      secureRandom = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    return secureRandom;
  }

  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata);
}
