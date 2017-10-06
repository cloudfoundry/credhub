package io.pivotal.security.view;

import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.domain.UserCredentialVersion;

public class UserView extends CredentialView {
  public UserView(UserCredentialVersion userCredential) {
    super(
        userCredential.getVersionCreatedAt(),
        userCredential.getUuid(),
        userCredential.getName(),
        userCredential.getCredentialType(),
        new UserCredentialValue(userCredential.getUsername(), userCredential.getPassword(), userCredential.getSalt())
    );
  }
}
