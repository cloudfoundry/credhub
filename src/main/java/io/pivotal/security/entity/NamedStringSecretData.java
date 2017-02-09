package io.pivotal.security.entity;

public abstract class NamedStringSecretData<T extends NamedStringSecretData> extends NamedSecretData<T> {

  public NamedStringSecretData() {
  }

  public NamedStringSecretData(String name) {
    super(name);
  }

  public String getValue() {
    return SecretEncryptionHelperProvider.getInstance().retrieveClearTextValue(this);
  }

  public NamedStringSecretData setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedValue(this, value);
    return this;
  }

  public abstract String getSecretType();
}
