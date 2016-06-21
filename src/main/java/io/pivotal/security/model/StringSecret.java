package io.pivotal.security.model;

import io.pivotal.security.entity.NamedStringSecret;

import javax.validation.constraints.NotNull;

public class StringSecret implements Secret<NamedStringSecret> {

  @NotNull
  public String value;

  public final String type = "value";

  public StringSecret(String secretValue) {
    value = secretValue;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public String getType() {
    return type;
  }

  @Override
  public void populateEntity(NamedStringSecret entity) {
    entity.setValue(getValue());
  }

  public String getValue() {
    return value;
  }
}