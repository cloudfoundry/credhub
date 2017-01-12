package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.RsaView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;

@Component
public class RsaGenerator implements SecretGenerator<RsaSecretParameters, RsaView> {

  @Autowired
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Override
  public RsaView generateSecret(RsaSecretParameters parameters) {
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(parameters.getKeyLength());
      return new RsaView(null, null, null, CertificateFormatter.pemOf(keyPair.getPublic()), CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
