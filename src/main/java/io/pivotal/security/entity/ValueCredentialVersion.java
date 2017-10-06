package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(ValueCredentialVersion.CREDENTIAL_TYPE)
public class ValueCredentialVersion extends CredentialVersion<ValueCredentialVersion> {

  public static final String CREDENTIAL_TYPE = "value";

  public ValueCredentialVersion() {
  }

  public ValueCredentialVersion(String name) {
    super(name);
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
