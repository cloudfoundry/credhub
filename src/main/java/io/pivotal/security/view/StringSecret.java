package io.pivotal.security.view;

import io.pivotal.security.entity.NamedStringSecret;

import javax.validation.constraints.NotNull;

public class StringSecret extends Secret<NamedStringSecret, StringSecret> {

  @NotNull
  public String value;

  public StringSecret(String secretValue) {
    value = secretValue;
  }

  public StringSecret setValue(String value) {
    this.value = value;
    return this;
  }

  @Override
  public String getType() {
    return "value";
  }

  @Override
  public void populateEntity(NamedStringSecret entity) {
    entity.setValue(getValue());
  }

  public String getValue() {
    return value;
  }
}