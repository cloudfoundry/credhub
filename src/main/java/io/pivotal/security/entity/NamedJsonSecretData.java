package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(NamedJsonSecretData.SECRET_TYPE)
public class NamedJsonSecretData extends NamedSecretData<NamedJsonSecretData> {

  public static final String SECRET_TYPE = "json";

  public NamedJsonSecretData() {
  }

  public NamedJsonSecretData(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  @Override
  public void copyIntoImpl(NamedJsonSecretData copy) {
  }
}
