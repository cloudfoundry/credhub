package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.RsaGenerationParameters;
import org.cloudfoundry.credhub.utils.CertificateFormatter;

@Component
public class RsaGenerator implements CredentialGenerator<RsaCredentialValue> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  RsaGenerator(final LibcryptoRsaKeyPairGenerator keyGenerator) {
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
