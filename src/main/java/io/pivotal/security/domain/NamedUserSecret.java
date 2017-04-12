package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedUserSecretData;

public class NamedUserSecret extends NamedSecret<NamedUserSecret> {
  private final NamedUserSecretData delegate;

  public static NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    NamedUserSecret namedUserSecret = new NamedUserSecret();
    namedUserSecret.copyNameReferenceFrom(existing);
    return namedUserSecret;
  }

  public NamedUserSecret() {
    this(new NamedUserSecretData());
  }

  public NamedUserSecret(NamedUserSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedUserSecret(String name) {
    this(new NamedUserSecretData(name));
  }

  @Override
  public String getSecretType() {
    return null;
  }

  @Override
  public void rotate() {

  }
}
