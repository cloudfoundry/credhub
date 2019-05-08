package org.cloudfoundry.credhub.views;

import java.time.Instant;
import java.util.Objects;

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

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    final CertificateView that = (CertificateView) o;
    return Objects.equals(version, that.version) &&
      Objects.equals(expiryDate, that.expiryDate);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), version, expiryDate);
  }
}
