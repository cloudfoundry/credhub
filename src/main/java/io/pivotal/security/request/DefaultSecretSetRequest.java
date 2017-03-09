package io.pivotal.security.request;

import javax.validation.constraints.NotNull;

public class DefaultSecretSetRequest extends BaseSecretSetRequest {
  @NotNull(message = "error.missing_value")
  private Object value;

  public Object getValue() {
    return value;
  }

  public void setValue(Object value) {
    this.value = value;
  }
}
