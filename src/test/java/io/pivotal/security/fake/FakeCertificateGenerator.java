package io.pivotal.security.fake;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.CertificateSecret;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Primary
@Profile("FakeCertificateGenerator")
public class FakeCertificateGenerator implements SecretGenerator<CertificateSecretParameters, CertificateSecret> {
  @Override
  public CertificateSecret generateSecret(CertificateSecretParameters parameters) {
    final String ca = parameters.getCa();
    return new CertificateSecret(null, null, String.format("the certificate for %s", ca != null ? ca : "default"), "generated certificate", "generated private key");
  }
}
