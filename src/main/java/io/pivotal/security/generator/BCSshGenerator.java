package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.SshSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

@Component
public class BCSshGenerator implements SecretGenerator<SshSecretParameters, SshSecret> {
  @Autowired
  KeyPairGenerator keyGenerator;

  @Override
  public SshSecret generateSecret(SshSecretParameters parameters) {
    keyGenerator.initialize(parameters.getKeyLength());
    final java.security.KeyPair keyPair = keyGenerator.generateKeyPair();

    try {
      String sshComment = parameters.getSshComment();
      String sshCommentMessage = StringUtils.isEmpty(sshComment) ? "" : " " + sshComment;

      String publicKey = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + sshCommentMessage;
      String privateKey = CertificateFormatter.pemOf(keyPair.getPrivate());

      return new SshSecret(null, null, publicKey, privateKey);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
