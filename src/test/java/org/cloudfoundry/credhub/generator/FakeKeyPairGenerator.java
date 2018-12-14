package org.cloudfoundry.credhub.generator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.springframework.stereotype.Component;

@Component
public class FakeKeyPairGenerator {

  private static final int KEY_LENGTH_FOR_TESTING = 1024;

  public KeyPair generate() throws NoSuchProviderException, NoSuchAlgorithmException {
    final KeyPairGenerator generator = KeyPairGenerator
      .getInstance("RSA");
    generator.initialize(KEY_LENGTH_FOR_TESTING);
    return generator.generateKeyPair();
  }
}
