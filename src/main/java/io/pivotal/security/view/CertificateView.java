package io.pivotal.security.view;

import io.pivotal.security.domain.CertificateCredentialVersion;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {
  private CertificateCredentialVersion version;

  CertificateView() { /* Jackson */ }

  public CertificateView(CertificateCredentialVersion version) {
    super(
        version.getVersionCreatedAt(),
        version.getUuid(),
        version.getName(),
        version.getCredentialType(),
        null
    );
    this.version = version;
  }

  @Override
  public Object getValue() {
    return new CertificateValueView(version);
  }

  public boolean getTransitional() {
    return version.isVersionTransitional();
  }
}
