package io.pivotal.security.view;

import io.pivotal.security.domain.NamedValueSecret;

@SuppressWarnings("unused")
public class ValueView extends SecretView {

  public ValueView() {}

  ValueView(NamedValueSecret namedValueSecret) {
    super(
        namedValueSecret.getVersionCreatedAt(),
        namedValueSecret.getUuid(),
        namedValueSecret.getName(),
        namedValueSecret.getSecretType(),
        namedValueSecret.getValue()
    );
  }
}
