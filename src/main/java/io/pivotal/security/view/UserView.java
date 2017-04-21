package io.pivotal.security.view;

import io.pivotal.security.domain.UserCredential;

public class UserView extends CredentialView {
  public UserView(UserCredential userCredential) {
    super(
        userCredential.getVersionCreatedAt(),
        userCredential.getUuid(),
        userCredential.getName(),
        userCredential.getCredentialType(),
        new User(userCredential.getUsername(), userCredential.getPassword()));
  }
}
