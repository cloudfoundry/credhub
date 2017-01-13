package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public class Credential {
  private String name;
  private Instant versionCreatedAt;

  public Credential(String name, Instant versionCreatedAt) {
    this.name = name;
    this.versionCreatedAt = versionCreatedAt;
  }

  @JsonProperty
  public String getName() {
    return name;
  }

  @JsonProperty("version_created_at")
  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
  }
}
