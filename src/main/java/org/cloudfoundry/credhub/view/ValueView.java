package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;

@SuppressWarnings("unused")
public class ValueView extends CredentialView {

  public ValueView() {}

  ValueView(ValueCredentialVersion valueCredential) {
    super(
        valueCredential.getVersionCreatedAt(),
        valueCredential.getUuid(),
        valueCredential.getName(),
        valueCredential.getCredentialType(),
        new StringCredentialValue((String) valueCredential.getValue())
    );
  }
}
