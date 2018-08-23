package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;

import java.time.Instant;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {
  private CertificateCredentialVersion version;

  private Instant expiryDate;

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
    this.expiryDate = version.getExpiryDate();
  }

  @Override
  public CredentialValue getValue() {
    return new CertificateValueView(version);
  }

  public boolean getTransitional() {
    return version.isVersionTransitional();
  }

  public Instant getExpiryDate() {
    return expiryDate;
  }
}
