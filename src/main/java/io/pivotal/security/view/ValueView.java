package io.pivotal.security.view;

import io.pivotal.security.domain.NamedValueSecret;

class ValueView extends SecretView {

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
