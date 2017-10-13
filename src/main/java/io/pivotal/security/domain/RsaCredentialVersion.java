package io.pivotal.security.domain;

import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.entity.RsaCredentialVersionData;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.RsaGenerationParameters;

public class RsaCredentialVersion extends CredentialVersion<RsaCredentialVersion> {

  private RsaCredentialVersionData delegate;

  public RsaCredentialVersion(RsaCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public RsaCredentialVersion(String name) {
    this(new RsaCredentialVersionData(name));
  }

  public RsaCredentialVersion() {
    this(new RsaCredentialVersionData());
  }

  public RsaCredentialVersion(RsaCredentialValue rsaValue, Encryptor encryptor) {
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

  public RsaCredentialVersion setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return this;
  }

  public String getPrivateKey() {
    return (String) super.getValue();
  }

  public RsaCredentialVersion setPrivateKey(String privateKey) {
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
  public boolean matchesGenerationParameters(GenerationParameters generationParameters) {
    return ((RsaGenerationParameters) generationParameters).getKeyLength() == getKeyLength();
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }
}
