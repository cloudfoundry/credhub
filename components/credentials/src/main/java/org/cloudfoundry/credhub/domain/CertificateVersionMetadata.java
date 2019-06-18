package org.cloudfoundry.credhub.domain;

import java.time.Instant;
import java.util.UUID;

public class CertificateVersionMetadata {

  private UUID id;
  private Instant expiryDate;
  private boolean transitional;
  private boolean certificateAuthority;
  private boolean selfSigned;

  public CertificateVersionMetadata(
    final UUID id,
    final Instant expiryDate,
    final boolean transitional,
    final boolean certificateAuthority,
    final boolean selfSigned
  ) {

    this.id = id;
    this.expiryDate = expiryDate;
    this.transitional = transitional;
    this.certificateAuthority = certificateAuthority;
    this.selfSigned = selfSigned;
  }

  public UUID getId() {
    return id;
  }

  public void setId(final UUID id) {
    this.id = id;
  }

  public Instant getExpiryDate() {
    return expiryDate;
  }

  public void setExpiryDate(final Instant expiryDate) {
    this.expiryDate = expiryDate;
  }

  public boolean isTransitional() {
    return transitional;
  }

  public void setTransitional(final boolean transitional) {
    this.transitional = transitional;
  }

  public boolean isCertificateAuthority() {
    return certificateAuthority;
  }

  public void setCertificateAuthority(final boolean certificateAuthority) {
    this.certificateAuthority = certificateAuthority;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public void setSelfSigned(final boolean selfSigned) {
    this.selfSigned = selfSigned;
  }
}
