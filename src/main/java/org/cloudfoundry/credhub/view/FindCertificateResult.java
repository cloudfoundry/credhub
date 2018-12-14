package org.cloudfoundry.credhub.view;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FindCertificateResult extends FindCredentialResult {
  private final Instant expiryDate;

  public FindCertificateResult(final Instant versionCreatedAt, final String name, final Instant expiryDate) {
    super(versionCreatedAt, name);
    this.expiryDate = expiryDate;
  }

  @JsonProperty
  public Instant getExpiryDate() {
    return expiryDate;
  }
}
