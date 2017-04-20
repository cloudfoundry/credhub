package io.pivotal.security.view;

import io.pivotal.security.domain.JsonCredential;

@SuppressWarnings("unused")
public class JsonView extends CredentialView {

  JsonView() {  /* Jackson */ }

  JsonView(JsonCredential namedJsonSecret) {
    super(
        namedJsonSecret.getVersionCreatedAt(),
        namedJsonSecret.getUuid(),
        namedJsonSecret.getName(),
        namedJsonSecret.getSecretType(),
        namedJsonSecret.getValue()
    );
  }
}
