package io.pivotal.security.domain;

import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.entity.SshCredentialVersion;
import io.pivotal.security.util.SshPublicKeyParser;

public class SshCredential extends Credential<SshCredential> {

  private SshCredentialVersion delegate;

  public SshCredential(SshCredentialVersion delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public SshCredential(String name) {
    this(new SshCredentialVersion(name));
  }

  public SshCredential() {
    this(new SshCredentialVersion());
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
