package io.pivotal.security.domain;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.entity.ValueCredentialVersion;

public class ValueCredential extends Credential<ValueCredential> {

  private ValueCredentialVersion delegate;

  public ValueCredential(ValueCredentialVersion delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public ValueCredential(String name) {
    this(new ValueCredentialVersion(name));
  }

  public ValueCredential() {
    this(new ValueCredentialVersion());
  }

  public ValueCredential(StringCredentialValue value, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setValue(value.getStringCredential());
  }

  public ValueCredential setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }

    return super.setValue(value);
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }


  public void rotate() {
    String decryptedValue = (String) this.getValue();
    this.setValue(decryptedValue);
  }

}
