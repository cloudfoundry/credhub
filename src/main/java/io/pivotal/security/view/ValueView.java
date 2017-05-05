package io.pivotal.security.view;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.domain.ValueCredential;

@SuppressWarnings("unused")
public class ValueView extends CredentialView {

  public ValueView() {}

  ValueView(ValueCredential valueCredential) {
    super(
        valueCredential.getVersionCreatedAt(),
        valueCredential.getUuid(),
        valueCredential.getName(),
        valueCredential.getCredentialType(),
        new StringCredentialValue(valueCredential.getValue())
    );
  }
}
