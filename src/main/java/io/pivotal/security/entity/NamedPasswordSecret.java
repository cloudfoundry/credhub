package io.pivotal.security.entity;

import io.pivotal.security.view.StringSecret;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "PasswordSecret")
@DiscriminatorValue("password")
public class NamedPasswordSecret extends NamedStringSecret<NamedPasswordSecret> {

  @SuppressWarnings("unused")
  public NamedPasswordSecret() {
  }

  public NamedPasswordSecret(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return "password";
  }
}