package io.pivotal.security.generator;

import io.pivotal.security.service.EncryptionConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
class RsaKeyPairGenerator {

  @Autowired
  EncryptionConfiguration encryptionConfiguration;

  public KeyPair generateKeyPair(int keyLength) {
    try {
      final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", encryptionConfiguration.getProvider());
      keyGenerator.initialize(keyLength);
      return keyGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
