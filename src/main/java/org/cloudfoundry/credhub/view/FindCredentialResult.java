package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public class FindCredentialResult {
  private final Instant versionCreatedAt;
  private final String name;

  public FindCredentialResult(Instant versionCreatedAt, String name) {
    this.versionCreatedAt = versionCreatedAt;
    this.name = name;
  }

  @JsonProperty
  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
  }

  @com.fasterxml.jackson.annotation.JsonProperty("name")
  public String getName() {
    return name;
  }
}
