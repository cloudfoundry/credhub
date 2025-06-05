package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.SshGenerationParameters;
import org.cloudfoundry.credhub.utils.CertificateFormatter;

@Component
public class SshGenerator implements CredentialGenerator<SshCredentialValue> {

  private final RsaKeyPairGenerator keyGenerator;

  @Autowired
  public SshGenerator(final RsaKeyPairGenerator keyGenerator) {
    super();
    this.keyGenerator = keyGenerator;
  }

  @Override
  public SshCredentialValue generateCredential(final GenerationParameters p) {
    final SshGenerationParameters params = (SshGenerationParameters) p;
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      final String sshComment = params.getSshComment();
      final String sshCommentMessage = StringUtils.hasLength(sshComment) ? " " + sshComment : "";

      final String publicKey =
        CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + sshCommentMessage;
      final String privateKey = CertificateFormatter.pemOf(keyPair.getPrivate());

      return new SshCredentialValue(publicKey, privateKey, null);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }
}
