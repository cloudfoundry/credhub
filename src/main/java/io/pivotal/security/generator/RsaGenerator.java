package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.util.CertificateFormatter;
import java.security.KeyPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RsaGenerator implements SecretGenerator<RsaSecretParameters, RsaKey> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  RsaGenerator(LibcryptoRsaKeyPairGenerator keyGenerator) {
    this.keyGenerator = keyGenerator;
  }

  @Override
  public RsaKey generateSecret(RsaSecretParameters parameters) {
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(parameters.getKeyLength());
      return new RsaKey(CertificateFormatter.pemOf(keyPair.getPublic()),
          CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
