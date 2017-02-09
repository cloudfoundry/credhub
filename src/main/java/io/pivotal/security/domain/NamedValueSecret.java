package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedValueSecret extends NamedStringSecret<NamedValueSecret> {
  private NamedValueSecretData delegate;

  public NamedValueSecret(NamedValueSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedValueSecret(String name) {
    this(new NamedValueSecretData(name));
  }

  public NamedValueSecret() {
    this(new NamedValueSecretData());
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  void copyIntoImpl(NamedValueSecret copy) {
    delegate.copyIntoImpl(copy.delegate);
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }
}
