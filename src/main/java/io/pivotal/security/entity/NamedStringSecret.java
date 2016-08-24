package io.pivotal.security.entity;

import io.pivotal.security.view.StringSecret;

import java.util.Objects;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
public class NamedStringSecret extends NamedSecret<NamedStringSecret> {

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public String getValue() {
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public NamedStringSecret setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }
    new SecretEncryptionHelper().refreshEncryptedValue(this, value);
    return this;
  }

  @Override
  public StringSecret generateView() {
    return new StringSecret(getValue()).setUpdatedAt(getUpdatedAt());
  }

  @Override
  public StringSecret getViewInstance() {
    return new StringSecret();
  }
}