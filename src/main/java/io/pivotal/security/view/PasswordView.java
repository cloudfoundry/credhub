package io.pivotal.security.view;

import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.domain.PasswordCredential;

@SuppressWarnings("unused")
public class PasswordView extends CredentialView {

  public PasswordView() {}

  public PasswordView(PasswordCredential passwordCredential) {
    super(
        passwordCredential.getVersionCreatedAt(),
        passwordCredential.getUuid(),
        passwordCredential.getName(),
        passwordCredential.getCredentialType(),
        new StringCredential(passwordCredential.getPassword())
    );
  }
}
