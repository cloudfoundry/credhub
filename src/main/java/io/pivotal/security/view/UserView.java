package io.pivotal.security.view;

import io.pivotal.security.domain.UserCredential;

public class UserView extends CredentialView {
  public UserView(UserCredential namedSecret) {
    super(
        namedSecret.getVersionCreatedAt(),
        namedSecret.getUuid(),
        namedSecret.getName(),
        namedSecret.getSecretType(),
        new User(namedSecret.getUsername(), namedSecret.getPassword()));
  }
}
