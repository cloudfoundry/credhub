package io.pivotal.security.generator;

import org.springframework.stereotype.Component;
import sun.security.rsa.SunRsaSign;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
class BCRsaKeyPairGenerator {

  public synchronized KeyPair generateKeyPair(int keyLength) throws NoSuchAlgorithmException {
    final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", new SunRsaSign());
    keyGenerator.initialize(keyLength);
    return keyGenerator.generateKeyPair();
  }
}
