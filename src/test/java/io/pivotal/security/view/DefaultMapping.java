package io.pivotal.security.view;

import io.pivotal.security.entity.NamedSecret;

import java.security.NoSuchAlgorithmException;

public abstract class DefaultMapping implements SecretKind.CheckedMapping<NamedSecret, NamedSecret, NoSuchAlgorithmException> {
  @Override
  public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret ssh(SecretKind secretKind, NamedSecret namedSecret) {
    return namedSecret;
  }

  @Override
  public NamedSecret rsa(SecretKind secretKind, NamedSecret namedSecret) {
    return namedSecret;
  }
}
