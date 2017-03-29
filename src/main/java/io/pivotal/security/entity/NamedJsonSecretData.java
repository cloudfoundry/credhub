package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
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
  public SecretKind getKind() {
    return null;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  @Override
  public void copyIntoImpl(NamedJsonSecretData copy) {
  }
}
