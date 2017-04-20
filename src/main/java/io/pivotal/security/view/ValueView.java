package io.pivotal.security.view;

import io.pivotal.security.domain.ValueCredential;

@SuppressWarnings("unused")
public class ValueView extends CredentialView {

  public ValueView() {}

  ValueView(ValueCredential namedValueSecret) {
    super(
        namedValueSecret.getVersionCreatedAt(),
        namedValueSecret.getUuid(),
        namedValueSecret.getName(),
        namedValueSecret.getSecretType(),
        namedValueSecret.getValue()
    );
  }
}
