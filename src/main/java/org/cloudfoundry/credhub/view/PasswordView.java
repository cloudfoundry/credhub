package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;

@SuppressWarnings("unused")
public class PasswordView extends CredentialView {

  public PasswordView() {}

  public PasswordView(PasswordCredentialVersion passwordCredential) {
    super(
        passwordCredential.getVersionCreatedAt(),
        passwordCredential.getUuid(),
        passwordCredential.getName(),
        passwordCredential.getCredentialType(),
        new StringCredentialValue(passwordCredential.getPassword())
    );
  }
}
