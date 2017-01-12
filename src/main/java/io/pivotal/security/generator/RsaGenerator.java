package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;

@Component
public class RsaGenerator implements SecretGenerator<RsaSecretParameters, RsaKey> {

  @Autowired
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Override
  public RsaKey generateSecret(RsaSecretParameters parameters) {
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(parameters.getKeyLength());
      return new RsaKey(CertificateFormatter.pemOf(keyPair.getPublic()), CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
