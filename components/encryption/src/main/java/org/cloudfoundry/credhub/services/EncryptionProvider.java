package org.cloudfoundry.credhub.services;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptedValue;

public interface EncryptionProvider {

  EncryptedValue encrypt(EncryptionKey key, String value) throws Exception;

  String decrypt(EncryptionKey key, byte[] encryptedValue, byte[] nonce) throws Exception;

  default SecureRandom getSecureRandom() {
    SecureRandom secureRandom = null;

    try {
      secureRandom = SecureRandom.getInstance("SHA1PRNG");
    } catch (final NoSuchAlgorithmException e) {
      LogManager.getLogger().log(Level.ALL, e.getMessage());
    }

    return secureRandom;
  }

  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata);
}
