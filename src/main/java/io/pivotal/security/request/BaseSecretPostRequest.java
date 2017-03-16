package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class BaseSecretPostRequest extends BaseSecretRequest {
  @JsonProperty(defaultValue = "false")
  private boolean regenerate;

  public boolean isRegenerate() {
    return regenerate;
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }

  public void validate() {
  }
}
