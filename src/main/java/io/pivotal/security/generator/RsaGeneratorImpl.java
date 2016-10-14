package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.RsaSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;

@Component
public class RsaGeneratorImpl implements SecretGenerator<RsaSecretParameters, RsaSecret> {

  @Autowired
  RsaKeyPairGenerator keyGenerator;

  @Override
  public RsaSecret generateSecret(RsaSecretParameters parameters) {
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(parameters.getKeyLength());
      return new RsaSecret(null, null, CertificateFormatter.pemOf(keyPair.getPublic()), CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
