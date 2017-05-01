package io.pivotal.security.domain;

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

  public static ValueCredential createNewVersion(ValueCredential existing, String name,
      String value, Encryptor encryptor) {
    ValueCredential credential;

    if (existing == null) {
      credential = new ValueCredential(name);
    } else {
      credential = new ValueCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setEncryptor(encryptor);
    credential.setValue(value);
    return credential;
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
