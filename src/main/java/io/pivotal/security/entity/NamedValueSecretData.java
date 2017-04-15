package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(NamedValueSecretData.SECRET_TYPE)
public class NamedValueSecretData extends NamedSecretData<NamedValueSecretData> {

  public static final String SECRET_TYPE = "value";

  public NamedValueSecretData() {
  }

  public NamedValueSecretData(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }
}
