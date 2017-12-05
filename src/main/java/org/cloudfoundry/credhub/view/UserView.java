package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;

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
