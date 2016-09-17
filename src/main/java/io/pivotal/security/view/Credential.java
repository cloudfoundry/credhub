package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public class Credential {
  private String name;
  private Instant updatedAt;

  public Credential(String name, Instant updatedAt) {
    this.name = name;
    this.updatedAt = updatedAt;
  }

  @JsonProperty
  public String getName() {
    return name;
  }

  @JsonProperty("updated_at")
  public Instant getUpdatedAt() {
    return updatedAt;
  }
}
