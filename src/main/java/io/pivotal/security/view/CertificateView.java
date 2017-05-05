package io.pivotal.security.view;

import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.credential.CertificateCredentialValue;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {

  CertificateView() { /* Jackson */ }

  CertificateView(CertificateCredential certificateCredential) {
    super(
        certificateCredential.getVersionCreatedAt(),
        certificateCredential.getUuid(),
        certificateCredential.getName(),
        certificateCredential.getCredentialType(),
        new CertificateCredentialValue(certificateCredential.getCa(), certificateCredential.getCertificate(),
            certificateCredential.getPrivateKey(), null)
    );
  }
}
