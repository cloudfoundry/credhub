package io.pivotal.security.generator;

import io.pivotal.security.helper.SpectrumHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

@Component
public class FakeKeyPairGenerator {

  private static final int KEY_LENGTH_FOR_TESTING = 1024;

  public KeyPair generate() throws NoSuchProviderException, NoSuchAlgorithmException {
    SpectrumHelper.getBouncyCastleProvider(); // has side effect of setting up the BouncyCastleProvider
    KeyPairGenerator generator = KeyPairGenerator
        .getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    generator.initialize(KEY_LENGTH_FOR_TESTING);
    return generator.generateKeyPair();
  }
}
