package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

@SuppressWarnings("PMD.UnnecessaryConstructor")
@Component
public class RsaKeyPairGenerator {

  @Autowired
  public RsaKeyPairGenerator() {
    super();
  }

  public synchronized KeyPair generateKeyPair(final int keyLength)
    throws NoSuchProviderException, NoSuchAlgorithmException {
    final BouncyCastleFipsProvider bouncyCastleProvider = new BouncyCastleFipsProvider();
    Security.addProvider(bouncyCastleProvider);

    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
    generator.initialize(keyLength);
    return generator.generateKeyPair();
  }
}
