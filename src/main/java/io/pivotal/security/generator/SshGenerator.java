package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

@Component
public class SshGenerator implements SecretGenerator<SshSecretParameters, SshKey> {

  @Autowired
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Override
  public SshKey generateSecret(SshSecretParameters parameters) {
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(parameters.getKeyLength());
      String sshComment = parameters.getSshComment();
      String sshCommentMessage = StringUtils.isEmpty(sshComment) ? "" : " " + sshComment;

      String publicKey = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + sshCommentMessage;
      String privateKey = CertificateFormatter.pemOf(keyPair.getPrivate());

      return new SshKey(publicKey, privateKey);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
