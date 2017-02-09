package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedStringSecretData;

public abstract class NamedStringSecret<T extends NamedStringSecret> extends NamedSecret<T> {

  private NamedStringSecretData delegate;

  public NamedStringSecret(NamedStringSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public String getValue() {
    return delegate.getValue();
  }

  public NamedStringSecret setValue(String value) {
    delegate.setValue(value);
    return this;
  }
}
