package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.RsaGenerationParameters;
import org.cloudfoundry.credhub.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;

@Component
public class RsaGenerator implements CredentialGenerator<RsaCredentialValue> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  RsaGenerator(LibcryptoRsaKeyPairGenerator keyGenerator) {
    this.keyGenerator = keyGenerator;
  }

  @Override
  public RsaCredentialValue generateCredential(GenerationParameters p) {
    RsaGenerationParameters params = (RsaGenerationParameters) p;
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      return new RsaCredentialValue(CertificateFormatter.pemOf(keyPair.getPublic()),
          CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
