package io.pivotal.security.entity;

public abstract class NamedStringSecret<T extends NamedStringSecret> extends NamedSecret<T> {

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public String getValue() {
    return SecretEncryptionHelperProvider.getInstance().retrieveClearTextValue(this);
  }

  public NamedStringSecret setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedValue(this, value);
    return this;
  }

  public abstract String getSecretType();
}
