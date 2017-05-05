package io.pivotal.security.domain;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.service.Encryption;

public class ValueCredential extends Credential<ValueCredential> {

  private ValueCredentialData delegate;

  public ValueCredential(ValueCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public ValueCredential(String name) {
    this(new ValueCredentialData(name));
  }

  public ValueCredential() {
    this(new ValueCredentialData());
  }

  public ValueCredential(StringCredentialValue value, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setValue(value.getStringCredential());
  }

  public String getValue() {
    return encryptor.decrypt(new Encryption(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()));
  }

  public ValueCredential setValue(String value) {
    if (value == null) {
      throw new IllegalArgumentException("value cannot be null");
    }

    final Encryption encryption = encryptor.encrypt(value);
    delegate.setEncryptedValue(encryption.encryptedValue);
    delegate.setNonce(encryption.nonce);
    delegate.setEncryptionKeyUuid(encryption.canaryUuid);

    return this;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }


  public void rotate() {
    String decryptedValue = this.getValue();
    this.setValue(decryptedValue);
  }

}
