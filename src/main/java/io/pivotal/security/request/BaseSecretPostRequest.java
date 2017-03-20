package io.pivotal.security.request;

public abstract class BaseSecretPostRequest extends BaseSecretRequest {
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
