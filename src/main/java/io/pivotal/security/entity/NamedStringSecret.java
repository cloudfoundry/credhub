package io.pivotal.security.entity;

import io.pivotal.security.view.StringSecret;

import javax.persistence.*;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
@EntityListeners(NamedSecretEncryptionListener.class)
public class NamedStringSecret extends NamedSecret<NamedStringSecret> {

  @Transient
  private String value;

  @Column(nullable = false, length = 7016, name = "encrypted_value")
  private byte[] encryptedValue;

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public String getValue() {
    return value;
  }

  public NamedStringSecret setValue(String value) {
    this.value = value;
    return this;
  }

  protected byte[] getEncryptedValue() {
    return encryptedValue;
  }

  protected void setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue;
  }

  @Override
  public StringSecret generateView() {
    return new StringSecret(value).setUpdatedAt(getUpdatedAt());
  }
}