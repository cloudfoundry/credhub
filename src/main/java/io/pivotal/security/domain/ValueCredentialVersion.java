package io.pivotal.security.domain;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.entity.ValueCredentialVersionData;

public class ValueCredentialVersion extends CredentialVersion<ValueCredentialVersion> {

  private ValueCredentialVersionData delegate;

  public ValueCredentialVersion(ValueCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public ValueCredentialVersion(String name) {
    this(new ValueCredentialVersionData(name));
  }

  public ValueCredentialVersion() {
    this(new ValueCredentialVersionData());
  }

  public ValueCredentialVersion(StringCredentialValue value, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setValue(value.getStringCredential());
  }

  public ValueCredentialVersion setValue(String value) {
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
