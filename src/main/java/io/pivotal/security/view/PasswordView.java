package io.pivotal.security.view;

import io.pivotal.security.domain.NamedPasswordSecret;

class PasswordView extends SecretView {

  PasswordView(NamedPasswordSecret namedPasswordSecret) {
    super(
        namedPasswordSecret.getVersionCreatedAt(),
        namedPasswordSecret.getUuid(),
        namedPasswordSecret.getName(),
        namedPasswordSecret.getSecretType(),
        namedPasswordSecret.getPassword()
    );
  }
}
