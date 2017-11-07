package io.pivotal.security.view;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredentialVersion;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {
  CertificateView() { /* Jackson */ }

  CertificateView(CertificateCredentialVersion certificateCredential) {
    this(certificateCredential,
        new CertificateCredentialValue(certificateCredential.getCa(), certificateCredential.getCertificate(),
          certificateCredential.getPrivateKey(), null)
    );
  }

  public CertificateView(CertificateCredentialVersion version, CertificateCredentialValue value) {
    super(
        version.getVersionCreatedAt(),
        version.getUuid(),
        version.getName(),
        version.getCredentialType(),
        value
    );
  }
}
