package io.pivotal.security.entity;

import javax.validation.constraints.NotNull;

public class Secret {
  @NotNull
  private String value;

  public Secret() {
  }

  public Secret(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }

    Secret secret = (Secret) obj;

    return value.equals(secret.value);
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }
}
