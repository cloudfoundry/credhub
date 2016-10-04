package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.SshSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPairGenerator;

import static io.pivotal.security.generator.BcKeyPairGenerator.DEFAULT_RSA_KEY_LENGTH;

@Component
public class BCSshGenerator implements SecretGenerator<SshSecretParameters, SshSecret> {
  @Autowired
  KeyPairGenerator keyGenerator;

  @Override
  public SshSecret generateSecret(SshSecretParameters parameters) {
    keyGenerator.initialize(DEFAULT_RSA_KEY_LENGTH);
    final java.security.KeyPair keyPair = keyGenerator.generateKeyPair();

    try {
      return new SshSecret(null, null, CertificateFormatter.pemOf(keyPair.getPublic()), CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
