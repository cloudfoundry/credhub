package io.pivotal.security.view;

import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.domain.UserCredential;

public class UserView extends CredentialView {
  public UserView(UserCredential userCredential) {
    super(
        userCredential.getVersionCreatedAt(),
        userCredential.getUuid(),
        userCredential.getName(),
        userCredential.getCredentialType(),
        new UserCredentialValue(userCredential.getUsername(), userCredential.getPassword(), userCredential.getSalt())
    );
  }
}
