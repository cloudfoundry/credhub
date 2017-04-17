package io.pivotal.security.view;

import io.pivotal.security.domain.NamedUserSecret;

public class UserView extends SecretView {
  public UserView(NamedUserSecret namedSecret) {
    super(
        namedSecret.getVersionCreatedAt(),
        namedSecret.getUuid(),
        namedSecret.getName(),
        namedSecret.getSecretType(),
        new User(namedSecret.getUsername(), namedSecret.getPassword()));
  }
}
