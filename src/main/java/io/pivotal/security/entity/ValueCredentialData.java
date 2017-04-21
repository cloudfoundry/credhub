package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(ValueCredentialData.CREDENTIAL_TYPE)
public class ValueCredentialData extends CredentialData<ValueCredentialData> {

  public static final String CREDENTIAL_TYPE = "value";

  public ValueCredentialData() {
  }

  public ValueCredentialData(String name) {
    super(name);
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
