package org.cloudfoundry.credhub.view;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FindCredentialResult {
  private final Instant versionCreatedAt;
  private final String name;

  public FindCredentialResult(final Instant versionCreatedAt, final String name) {
    super();
    this.versionCreatedAt = versionCreatedAt;
    this.name = name;
  }

  @JsonProperty
  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }
}
