package io.pivotal.security.view;

import io.pivotal.security.domain.NamedPasswordSecret;

@SuppressWarnings("unused")
public class PasswordView extends SecretView {

  public PasswordView() {}

  public PasswordView(NamedPasswordSecret namedPasswordSecret) {
    super(
        namedPasswordSecret.getVersionCreatedAt(),
        namedPasswordSecret.getUuid(),
        namedPasswordSecret.getName(),
        namedPasswordSecret.getSecretType(),
        namedPasswordSecret.getPassword()
    );
  }
}
