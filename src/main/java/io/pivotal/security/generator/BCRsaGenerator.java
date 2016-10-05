package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.RsaSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPairGenerator;

@Component
public class BCRsaGenerator implements SecretGenerator<RsaSecretParameters, RsaSecret> {
  @Autowired
  KeyPairGenerator keyGenerator;

  @Override
  public RsaSecret generateSecret(RsaSecretParameters parameters) {
    keyGenerator.initialize(parameters.getKeyLength());
    final java.security.KeyPair keyPair = keyGenerator.generateKeyPair();

    try {
      return new RsaSecret(null, null, CertificateFormatter.pemOf(keyPair.getPublic()), CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
