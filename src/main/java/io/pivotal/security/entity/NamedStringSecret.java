package io.pivotal.security.entity;

import io.pivotal.security.model.StringSecret;

import javax.persistence.*;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
public class NamedStringSecret extends NamedSecret {

  @Column(nullable = false)
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
  public Object convertToModel() {
    return new StringSecret(value);
  }
}