package io.pivotal.security.view;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.domain.PasswordCredentialVersion;

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
