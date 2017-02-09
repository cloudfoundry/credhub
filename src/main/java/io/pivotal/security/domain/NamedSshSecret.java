package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedSshSecret extends NamedRsaSshSecret {

  private NamedSshSecretData delegate;

  public NamedSshSecret(NamedSshSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedSshSecret(String name) {
    this(new NamedSshSecretData(name));
  }

  public NamedSshSecret() {
    this(new NamedSshSecretData());
  }

  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  public int getKeyLength() {
    return delegate.getKeyLength();
  }

  public String getComment() {
    return delegate.getComment();
  }
}
