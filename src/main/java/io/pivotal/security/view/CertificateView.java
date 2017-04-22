package io.pivotal.security.view;

import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.credential.Certificate;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {

  CertificateView() { /* Jackson */ }

  CertificateView(CertificateCredential certificateCredential) {
    super(
        certificateCredential.getVersionCreatedAt(),
        certificateCredential.getUuid(),
        certificateCredential.getName(),
        certificateCredential.getCredentialType(),
        new Certificate(certificateCredential.getCa(), certificateCredential.getCertificate(),
            certificateCredential.getPrivateKey(), null)
    );
  }
}
