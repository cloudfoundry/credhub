package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.EncryptionServiceImpl;
import io.pivotal.security.view.StringSecret;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import java.util.Objects;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
public class NamedStringSecret extends NamedSecret<NamedStringSecret> {

  @Transient
  private String value;

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name) {
    super(name);
  }

  public String getValue() {
    try {
      EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
      return encryptionService.decrypt(getNonce(), getEncryptedValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public NamedStringSecret setValue(String value) {
    if (value == null) {
      throw new RuntimeException("value cannot be null");
    }
    if (!Objects.equals(this.value, value)) {
      try {
        EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
        EncryptionServiceImpl.Encryption encryption = encryptionService.encrypt(value);
        setNonce(encryption.nonce);
        setEncryptedValue(encryption.encryptedValue);
        this.value = value;
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
    return this;
  }

  @Override
  public StringSecret generateView() {
    return new StringSecret(getValue()).setUpdatedAt(getUpdatedAt());
  }
}