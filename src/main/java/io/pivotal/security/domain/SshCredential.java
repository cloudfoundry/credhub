package io.pivotal.security.domain;

import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.util.SshPublicKeyParser;

public class SshCredential extends Credential<SshCredential> {

  private SshCredentialData delegate;

  public SshCredential(SshCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public SshCredential(String name) {
    this(new SshCredentialData(name));
  }

  public SshCredential() {
    this(new SshCredentialData());
  }

  public SshCredential(SshCredentialValue sshValue, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setPublicKey(sshValue.getPublicKey());
    this.setPrivateKey(sshValue.getPrivateKey());
  }

  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public SshCredential setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return this;
  }

  public String getPrivateKey() {
      return (String) super.getValue();
  }

  public SshCredential setPrivateKey(String privateKey) {
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

  public int getKeyLength() {
    return new SshPublicKeyParser(getPublicKey()).getKeyLength();
  }

  public String getComment() {
    return new SshPublicKeyParser(getPublicKey()).getComment();
  }

  public String getFingerprint() {
    return new SshPublicKeyParser(getPublicKey()).getFingerprint();
  }
}
