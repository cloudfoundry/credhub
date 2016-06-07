package io.pivotal.security.model;

import javax.validation.constraints.NotNull;

public class StringSecret {

  @NotNull
  public String value;

  public final String type = "value";

  public StringSecret(String secretValue) {
    value = secretValue;
  }

  public void setValue(String value) {
    this.value = value;
  }
}