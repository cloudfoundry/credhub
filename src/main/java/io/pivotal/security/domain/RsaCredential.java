package io.pivotal.security.domain;

import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.entity.RsaCredentialData;

public class RsaCredential extends Credential<RsaCredential> {

  private RsaCredentialData delegate;

  public RsaCredential(RsaCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public RsaCredential(String name) {
    this(new RsaCredentialData(name));
  }

  public RsaCredential() {
    this(new RsaCredentialData());
  }

  public RsaCredential(RsaCredentialValue rsaValue, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setPublicKey(rsaValue.getPublicKey());
    this.setPrivateKey(rsaValue.getPrivateKey());
  }

  public int getKeyLength() {
    return delegate.getKeyLength();
  }

  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public RsaCredential setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return this;
  }

  public String getPrivateKey() {
    return (String) super.getValue();
  }

  public RsaCredential setPrivateKey(String privateKey) {
    if (privateKey != null) {
      super.setValue(privateKey);
    }
    return this;
  }

  public void rotate() {
    String decryptedValue = this.getPrivateKey();
    this.setPrivateKey(decryptedValue);
  }


  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }
}
