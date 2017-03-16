package io.pivotal.security.request;

public abstract class BaseSecretPostRequest extends BaseSecretRequest {
  private Boolean regenerate;

  public boolean isRegenerate() {
    return regenerate != null && regenerate;
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }

  public void validate() {
  }
}
