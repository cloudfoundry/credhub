package io.pivotal.security.view;

import io.pivotal.security.domain.PasswordCredential;

@SuppressWarnings("unused")
public class PasswordView extends CredentialView {

  public PasswordView() {}

  public PasswordView(PasswordCredential namedPasswordSecret) {
    super(
        namedPasswordSecret.getVersionCreatedAt(),
        namedPasswordSecret.getUuid(),
        namedPasswordSecret.getName(),
        namedPasswordSecret.getSecretType(),
        namedPasswordSecret.getPassword()
    );
  }
}
