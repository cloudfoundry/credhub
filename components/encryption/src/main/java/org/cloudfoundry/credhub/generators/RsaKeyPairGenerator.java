package org.cloudfoundry.credhub.generators;

import java.security.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

@SuppressWarnings("PMD.UnnecessaryConstructor")
@Component
public class RsaKeyPairGenerator {

  private final KeyPairGenerator generator;

  @Autowired
  public RsaKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
    super();
    final BouncyCastleFipsProvider bouncyCastleProvider = new BouncyCastleFipsProvider();
    Security.addProvider(bouncyCastleProvider);
    generator = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
  }

  static RsaKeyPairGenerator constructRsiKeyPairGeneratorForTesting(KeyPairGenerator generator) {
    return new RsaKeyPairGenerator(generator);
  }

  private RsaKeyPairGenerator(KeyPairGenerator generator) {
    super();
    this.generator = generator;
  }

  public synchronized KeyPair generateKeyPair(final int keyLength) {
    generator.initialize(keyLength);
    return generator.generateKeyPair();
  }
}
