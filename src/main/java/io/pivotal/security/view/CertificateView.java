package io.pivotal.security.view;

import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.credential.Certificate;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {

  CertificateView() { /* Jackson */ }

  CertificateView(CertificateCredential namedCertificateSecret) {
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
