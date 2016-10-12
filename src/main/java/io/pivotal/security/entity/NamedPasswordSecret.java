package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "PasswordSecret")
@DiscriminatorValue("password")
public class NamedPasswordSecret extends NamedStringSecret {

  @SuppressWarnings("unused")
  public NamedPasswordSecret() {
  }

  public NamedPasswordSecret(String name) {
    super(name);
  }

  public NamedPasswordSecret(String name, String value) {
    super(name, value);
  }

  @Override
  public String getSecretType() {
    return "password";
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.PASSWORD;
  }
}
