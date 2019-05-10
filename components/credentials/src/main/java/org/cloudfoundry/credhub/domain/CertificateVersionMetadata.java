package org.cloudfoundry.credhub.domain;

import java.time.Instant;
import java.util.UUID;

public class CertificateVersionMetadata {

  private UUID id;
  private Instant expiryDate;
  private boolean transitional;

  public CertificateVersionMetadata(final UUID id, final Instant expiryDate, final boolean transitional) {
    this.id = id;
    this.expiryDate = expiryDate;
    this.transitional = transitional;
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
}
