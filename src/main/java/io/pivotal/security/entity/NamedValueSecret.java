package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "ValueSecret")
@DiscriminatorValue(NamedValueSecret.SECRET_TYPE)
public class NamedValueSecret extends NamedStringSecret<NamedValueSecret> {

  public static final String SECRET_TYPE = "value";

  public NamedValueSecret() {
  }

  public NamedValueSecret(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  @Override
  void copyIntoImpl(NamedValueSecret copy) {
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.VALUE;
  }
}
