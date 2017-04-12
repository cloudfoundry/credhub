package io.pivotal.security.view;

import io.pivotal.security.domain.NamedJsonSecret;

@SuppressWarnings("unused")
public class JsonView extends SecretView {

  JsonView() {  /* Jackson */ }

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
