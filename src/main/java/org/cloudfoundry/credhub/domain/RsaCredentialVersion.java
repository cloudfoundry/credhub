package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.RsaGenerationParameters;

public class RsaCredentialVersion extends CredentialVersion {

  private final RsaCredentialVersionData delegate;

  public RsaCredentialVersion(final RsaCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public RsaCredentialVersion(final String name) {
    this(new RsaCredentialVersionData(name));
  }

  public RsaCredentialVersion() {
    this(new RsaCredentialVersionData());
  }

  public RsaCredentialVersion(final RsaCredentialValue rsaValue, final Encryptor encryptor) {
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

  public void setPublicKey(final String publicKey) {
    this.delegate.setPublicKey(publicKey);
  }

  public String getPrivateKey() {
    return (String) super.getValue();
  }

  public void setPrivateKey(final String privateKey) {
    if (privateKey != null) {
      super.setValue(privateKey);
    }
  }

  @Override
  public void rotate() {
    final String decryptedValue = this.getPrivateKey();
    this.setPrivateKey(decryptedValue);
  }

  @Override
  public boolean matchesGenerationParameters(final GenerationParameters generationParameters) {
    if (generationParameters == null) {
      return true;
    }

    return ((RsaGenerationParameters) generationParameters).getKeyLength() == getKeyLength();
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
