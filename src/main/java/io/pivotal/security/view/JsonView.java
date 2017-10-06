package io.pivotal.security.view;

import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.domain.JsonCredentialVersion;

@SuppressWarnings("unused")
public class JsonView extends CredentialView {

  JsonView() {  /* Jackson */ }

  JsonView(JsonCredentialVersion jsonCredential) {
    super(
        jsonCredential.getVersionCreatedAt(),
        jsonCredential.getUuid(),
        jsonCredential.getName(),
        jsonCredential.getCredentialType(),
        new JsonCredentialValue(jsonCredential.getValue())
    );
  }
}
