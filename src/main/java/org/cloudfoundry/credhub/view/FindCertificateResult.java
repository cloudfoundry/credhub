package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public class FindCertificateResult extends FindCredentialResult {
  private final Instant expiryDate;

  public FindCertificateResult(Instant versionCreatedAt, String name, Instant expiryDate) {
    super(versionCreatedAt, name);
    this.expiryDate = expiryDate;
  }

  @JsonProperty
  public Instant getExpiryDate() {
    return expiryDate;
  }
}
