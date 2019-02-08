package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.requests.GenerationParameters;

public class ValueCredentialVersion extends CredentialVersion {

  private final ValueCredentialVersionData delegate;

  public ValueCredentialVersion(final ValueCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public ValueCredentialVersion(final String name) {
    this(new ValueCredentialVersionData(name));
  }

  public ValueCredentialVersion() {
    this(new ValueCredentialVersionData());
  }

  public ValueCredentialVersion(final StringCredentialValue value, final Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setValue(value.getStringCredential());
  }

  @Override
  public void setValue(final String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }

    super.setValue(value);
  }

  @Override
  public boolean matchesGenerationParameters(final GenerationParameters generationParameters) {
    return generationParameters == null;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }


  @Override
  public void rotate() {
    final String decryptedValue = (String) this.getValue();
    this.setValue(decryptedValue);
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
