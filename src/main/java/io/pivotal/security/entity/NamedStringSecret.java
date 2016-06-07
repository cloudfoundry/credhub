package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@Table(name = "StringSecret")
@DiscriminatorValue("string_value")
public class NamedStringSecret extends NamedSecret {

  @Column(nullable = false)
  public String value;

  public NamedStringSecret() {
  }

  public NamedStringSecret(String name, String value) {
    super(name);
    this.value = value;
  }
}