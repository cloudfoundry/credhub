package io.pivotal.security.domain;

import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.entity.SshCredentialVersionData;
import io.pivotal.security.util.SshPublicKeyParser;

public class SshCredentialVersion extends CredentialVersion<SshCredentialVersion> {

  private SshCredentialVersionData delegate;

  public SshCredentialVersion(SshCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public SshCredentialVersion(String name) {
    this(new SshCredentialVersionData(name));
  }

  public SshCredentialVersion() {
    this(new SshCredentialVersionData());
  }

  public SshCredentialVersion(SshCredentialValue sshValue, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setPublicKey(sshValue.getPublicKey());
    this.setPrivateKey(sshValue.getPrivateKey());
  }

  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public SshCredentialVersion setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return this;
  }

  public String getPrivateKey() {
      return (String) super.getValue();
  }

  public SshCredentialVersion setPrivateKey(String privateKey) {
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
