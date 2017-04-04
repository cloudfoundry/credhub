package io.pivotal.security.generator;

import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

@Component
public class SshGenerator implements SecretGenerator<SshGenerationParameters, SshKey> {

  private LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  public SshGenerator(LibcryptoRsaKeyPairGenerator keyGenerator) {
    this.keyGenerator = keyGenerator;
  }

  @Override
  public SshKey generateSecret(SshGenerationParameters parameters) {
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(parameters.getKeyLength());
      String sshComment = parameters.getSshComment();
      String sshCommentMessage = StringUtils.isEmpty(sshComment) ? "" : " " + sshComment;

      String publicKey =
          CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + sshCommentMessage;
      String privateKey = CertificateFormatter.pemOf(keyPair.getPrivate());

      return new SshKey(publicKey, privateKey, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
