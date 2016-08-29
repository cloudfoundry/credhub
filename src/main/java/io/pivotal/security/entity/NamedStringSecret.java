package io.pivotal.security.entity;

import io.pivotal.security.view.StringSecret;

public abstract class NamedStringSecret<T> extends NamedSecret<T> {

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public String getValue() {
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public T setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }
    new SecretEncryptionHelper().refreshEncryptedValue(this, value);
    return (T) this;
  }

  @Override
  public StringSecret getViewInstance() {
    return new StringSecret(this.getSecretType(), this.getValue());
  }

  public abstract String getSecretType();
}