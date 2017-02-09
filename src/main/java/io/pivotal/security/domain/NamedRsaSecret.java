package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedRsaSecret extends NamedRsaSshSecret {

  private NamedRsaSecretData delegate;

  public NamedRsaSecret(NamedRsaSecretData delegate){
    super(delegate);
    this.delegate = delegate;
  }

  public NamedRsaSecret(String name) {
    this(new NamedRsaSecretData(name));
  }

  public NamedRsaSecret() {
    this(new NamedRsaSecretData());
  }

  public int getKeyLength(){
    return delegate.getKeyLength();
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }
}
