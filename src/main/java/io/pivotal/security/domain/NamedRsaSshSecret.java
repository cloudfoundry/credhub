package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedRsaSshSecretData;


public abstract class NamedRsaSshSecret extends NamedSecret<NamedRsaSshSecret> {

  private NamedRsaSshSecretData delegate;

  public NamedRsaSshSecret(NamedRsaSshSecretData delegate){
    super(delegate);
    this.delegate = delegate;
  }


  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public <T extends NamedRsaSshSecret> T setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return (T) this;
  }

  public String getPrivateKey() {
    return delegate.getPrivateKey();
  }

  public <T extends NamedRsaSshSecret> T setPrivateKey(String privateKey) {
    delegate.setPrivateKey(privateKey);
    return (T) this;
  }


}
