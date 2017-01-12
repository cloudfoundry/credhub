package io.pivotal.security.view;

import io.pivotal.security.entity.NamedCertificateSecret;

class CertificateView extends SecretView {
  CertificateView(NamedCertificateSecret namedCertificateSecret) {
    super(
        namedCertificateSecret.getVersionCreatedAt(),
        namedCertificateSecret.getUuid(),
        namedCertificateSecret.getName(),
        namedCertificateSecret.getSecretType(),
        new CertificateBody(namedCertificateSecret.getCa(), namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey())
    );
  }
}
