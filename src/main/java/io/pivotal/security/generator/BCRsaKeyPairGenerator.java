package io.pivotal.security.generator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
class BCRsaKeyPairGenerator {

  @Autowired
  BouncyCastleProvider provider;

  public synchronized KeyPair generateKeyPair(int keyLength) throws NoSuchAlgorithmException {
    final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", provider);
    keyGenerator.initialize(keyLength);
    return keyGenerator.generateKeyPair();
  }
}
