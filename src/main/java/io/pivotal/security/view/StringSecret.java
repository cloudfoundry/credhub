package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedStringSecret;

import javax.validation.constraints.NotNull;

public class StringSecret extends Secret<NamedStringSecret, StringSecret> {

  @NotNull
  @JsonProperty("value")
  private String value;

  @JsonProperty() // superclass also has this annotation
  private String type;

  public StringSecret() {}

  @Deprecated
  public StringSecret(String secretValue) {
    value = secretValue;
  }

  public StringSecret(String secretType, String secretValue) {
    this.type = secretType;
    this.value = secretValue;
  }

  public StringSecret setValue(String value) {
    this.value = value;
    return this;
  }

  @Override
  public String getType() {
    return this.type;
  }

  public StringSecret setType(String type) {
    this.type = type;
    return this;
  }

  @Override
  public StringSecret generateView(NamedStringSecret entity) {
    StringSecret result = super
        .generateView(entity)
        .setValue(entity.getValue())
        .setType(entity.getSecretType());
    return result;
  }

  @Override
  public void populateEntity(NamedStringSecret entity) {
    entity.setValue(getValue());
  }

  public String getValue() {
    return value;
  }
}