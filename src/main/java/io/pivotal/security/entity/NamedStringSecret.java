package io.pivotal.security.entity;

public abstract class NamedStringSecret extends NamedSecret {

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public NamedStringSecret(String name, String value) {
    super(name);
    setValue(value);
  }

  public String getValue() {
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public void setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }
    new SecretEncryptionHelper().refreshEncryptedValue(this, value);
  }

  public abstract String getSecretType();
}