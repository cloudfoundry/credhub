package org.cloudfoundry.credhub.generator;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.RsaGenerationParameters;
import org.cloudfoundry.credhub.util.CertificateFormatter;

@Component
public class RsaGenerator implements CredentialGenerator<RsaCredentialValue> {

  private final RsaKeyPairGenerator keyGenerator;

  @Autowired
  RsaGenerator(final RsaKeyPairGenerator keyGenerator) {
    super();
    this.keyGenerator = keyGenerator;
  }

  @Override
  public RsaCredentialValue generateCredential(final GenerationParameters p) {
    final RsaGenerationParameters params = (RsaGenerationParameters) p;
    try {
      final KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      return new RsaCredentialValue(CertificateFormatter.pemOf(keyPair.getPublic()),
        CertificateFormatter.pemOf(keyPair.getPrivate()));
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }
}
