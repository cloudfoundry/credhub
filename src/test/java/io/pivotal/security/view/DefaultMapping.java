package io.pivotal.security.view;

import io.pivotal.security.entity.NamedSecret;

import java.security.NoSuchAlgorithmException;

public abstract class DefaultMapping implements SecretKind.CheckedMapping<NamedSecret, NamedSecret, NoSuchAlgorithmException> {
  @Override
  public NamedSecret value(NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret password(NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret certificate(NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret ssh(NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret rsa(NamedSecret namedSecret) {
    return namedSecret;
  }
}
