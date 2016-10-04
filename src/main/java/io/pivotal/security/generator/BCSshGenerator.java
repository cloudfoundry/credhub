package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.SshSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPairGenerator;

@Component
public class BCSshGenerator implements SecretGenerator<SshSecretParameters, SshSecret> {
  @Autowired
  KeyPairGenerator keyGenerator;

  @Override
  public SshSecret generateSecret(SshSecretParameters parameters) {
    keyGenerator.initialize(parameters.getKeyLength());
    final java.security.KeyPair keyPair = keyGenerator.generateKeyPair();

    try {
      return new SshSecret(null, null, CertificateFormatter.pemOf(keyPair.getPublic()), CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
