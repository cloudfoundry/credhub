package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.SshGenerationParameters;
import org.cloudfoundry.credhub.util.SshPublicKeyParser;

public class SshCredentialVersion extends CredentialVersion<SshCredentialVersion> {

  private final SshPublicKeyParser parser;
  private SshCredentialVersionData delegate;

  public SshCredentialVersion(SshCredentialVersionData delegate) {
    this(delegate, new SshPublicKeyParser());
  }

  public SshCredentialVersion(SshCredentialVersionData delegate, SshPublicKeyParser keyParser) {
    super(delegate);
    this.delegate = delegate;
    this.parser = keyParser;
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
  public boolean matchesGenerationParameters(GenerationParameters generationParameters) {
    final SshGenerationParameters parameters = (SshGenerationParameters) generationParameters;
    return parameters.getKeyLength() == getKeyLength() && parameters.getSshComment().equals(getComment());
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
}
