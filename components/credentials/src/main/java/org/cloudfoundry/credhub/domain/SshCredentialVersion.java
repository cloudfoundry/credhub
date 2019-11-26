package org.cloudfoundry.credhub.domain;

import java.util.Objects;

import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.SshGenerationParameters;
import org.cloudfoundry.credhub.utils.SshPublicKeyParser;

public class SshCredentialVersion extends CredentialVersion {

  private final SshPublicKeyParser parser;
  private final SshCredentialVersionData delegate;

  public SshCredentialVersion(final SshCredentialVersionData delegate) {
    this(delegate, new SshPublicKeyParser());
  }

  public SshCredentialVersion(final SshCredentialVersionData delegate, final SshPublicKeyParser keyParser) {
    super(delegate);
    this.delegate = delegate;
    this.parser = keyParser;
  }

  public SshCredentialVersion(final String name) {
    this(new SshCredentialVersionData(name));
  }

  public SshCredentialVersion() {
    this(new SshCredentialVersionData());
  }

  public SshCredentialVersion(final SshCredentialValue sshValue, final Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setPublicKey(sshValue.getPublicKey());
    this.setPrivateKey(sshValue.getPrivateKey());
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

    final SshGenerationParameters parameters = (SshGenerationParameters) generationParameters;
    return parameters.getKeyLength() == getKeyLength() && Objects.equals(parameters.getSshComment(), getComment());
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public int getKeyLength() {
    parser.setPublicKey(getPublicKey());
    return parser.getKeyLength();
  }

  public String getComment() {
    parser.setPublicKey(getPublicKey());
    return parser.getComment();
  }

  public String getFingerprint() {
    parser.setPublicKey(getPublicKey());
    return parser.getFingerprint();
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
