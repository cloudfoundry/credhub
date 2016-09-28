package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.view.SecretKind;

public abstract class DefaultMapping implements SecretKind.Mapping<NamedSecret, NamedSecret> {
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
}
