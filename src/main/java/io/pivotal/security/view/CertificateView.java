package io.pivotal.security.view;

import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.secret.Certificate;

@SuppressWarnings("unused")
public class CertificateView extends SecretView {

  CertificateView() { /* Jackson */ }

  CertificateView(NamedCertificateSecret namedCertificateSecret) {
    super(
        namedCertificateSecret.getVersionCreatedAt(),
        namedCertificateSecret.getUuid(),
        namedCertificateSecret.getName(),
        namedCertificateSecret.getSecretType(),
        new Certificate(namedCertificateSecret.getCa(), namedCertificateSecret.getCertificate(),
            namedCertificateSecret.getPrivateKey())
    );
  }
}
