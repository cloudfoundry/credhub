package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.SshGenerationParameters;
import org.cloudfoundry.credhub.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

@Component
public class SshGenerator implements CredentialGenerator<SshCredentialValue> {

  private LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  public SshGenerator(LibcryptoRsaKeyPairGenerator keyGenerator) {
    this.keyGenerator = keyGenerator;
  }

  @Override
  public SshCredentialValue generateCredential(GenerationParameters p) {
    SshGenerationParameters params = (SshGenerationParameters) p;
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      String sshComment = params.getSshComment();
      String sshCommentMessage = StringUtils.isEmpty(sshComment) ? "" : " " + sshComment;

      String publicKey =
          CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + sshCommentMessage;
      String privateKey = CertificateFormatter.pemOf(keyPair.getPrivate());

      return new SshCredentialValue(publicKey, privateKey, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
