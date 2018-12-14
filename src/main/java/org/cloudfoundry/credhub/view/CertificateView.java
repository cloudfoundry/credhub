package org.cloudfoundry.credhub.view;

import java.time.Instant;

import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {
  private CertificateCredentialVersion version;

  private Instant expiryDate;

  CertificateView() {
    super(); /* Jackson */
  }

  public CertificateView(final CertificateCredentialVersion version) {
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

  public boolean isTransitional() {
    return version.isVersionTransitional();
  }

  public Instant getExpiryDate() {
    return expiryDate;
  }
}
