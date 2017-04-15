package io.pivotal.security.entity;

public class NamedUserSecretData extends NamedSecretData<NamedUserSecretData> {
  public NamedUserSecretData() {
    this(null);
  }

  public NamedUserSecretData(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return null;
  }
}
