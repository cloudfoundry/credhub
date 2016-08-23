package io.pivotal.security.entity;

import io.pivotal.security.view.StringSecret;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
public class NamedStringSecret extends NamedSecret<NamedStringSecret> implements SecretEncryptor {

  @Transient
  private String value;

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public String getValue() {
    return new SecretEncryptionHelper<NamedStringSecret>().decryptPrivateKey(this);
  }

  public NamedStringSecret setValue(String value) {
    if (value == null) {
      throw new RuntimeException("value cannot be null");
    }
    return new SecretEncryptionHelper<NamedStringSecret>().encryptPrivateKey(this, value);
  }

  public void setCachedItem(String value) {
    this.value = value;
  }

  public String getCachedItem() {
    return this.value;
  }

  @Override
  public StringSecret generateView() {
    return new StringSecret(getValue()).setUpdatedAt(getUpdatedAt());
  }
}