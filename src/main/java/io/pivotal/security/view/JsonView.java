package io.pivotal.security.view;

import io.pivotal.security.domain.NamedJsonSecret;

class JsonView extends SecretView {
  JsonView(NamedJsonSecret namedJsonSecret) {
    super(
        namedJsonSecret.getVersionCreatedAt(),
        namedJsonSecret.getUuid(),
        namedJsonSecret.getName(),
        namedJsonSecret.getSecretType(),
        namedJsonSecret.getValue()
    );
  }
}
