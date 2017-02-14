package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedValueSecret extends NamedSecret<NamedValueSecret> {
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

  public String getValue() {
    return delegate.getValue();
  }

  public NamedValueSecret setValue(String value) {
    delegate.setValue(value);
    return this;
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }
}
