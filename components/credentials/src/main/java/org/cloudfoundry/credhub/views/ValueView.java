package org.cloudfoundry.credhub.views;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;

@SuppressWarnings("unused")
public class ValueView extends CredentialView {

  public ValueView() {
    super();
  }

  ValueView(final ValueCredentialVersion valueCredential) {
    super(
      valueCredential.getVersionCreatedAt(),
      valueCredential.getUuid(),
      valueCredential.getName(),
      valueCredential.getCredentialType(),
      new StringCredentialValue((String) valueCredential.getValue())
    );
  }
}
