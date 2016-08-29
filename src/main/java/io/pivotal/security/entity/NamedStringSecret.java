package io.pivotal.security.entity;

import io.pivotal.security.view.StringSecret;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
public class NamedStringSecret extends NamedSecret<NamedStringSecret> {

  @Column(nullable = false)
  private String secretType;

  public NamedStringSecret() {
  }

  @Deprecated
  public NamedStringSecret(String name) {
    this(name, "value");
  }

  public NamedStringSecret(String name, String secretType) {
    super(name);
    this.setSecretType(secretType);
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
  public StringSecret getViewInstance() {
    StringSecret stringSecret = new StringSecret(this.getSecretType(), this.getValue());
    return stringSecret;
  }

  public String getSecretType() {
    return secretType;
  }

  public void setSecretType(String secretType) {
    if(!"value".equals(secretType) && !"password".equals(secretType)) {
      throw new IllegalArgumentException("secret type must be either 'value' or 'password'");
    }
    this.secretType = secretType;
  }
}