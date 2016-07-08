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

  @Column(nullable = false, length = 7000)
  private String value;

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

  @Override
  public StringSecret generateView() {
    return new StringSecret(value).setUpdatedAt(getUpdatedAt());
  }
}