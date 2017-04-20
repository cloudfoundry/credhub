package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class ValueCredential extends Credential<ValueCredential> {

  private NamedValueSecretData delegate;

  public ValueCredential(NamedValueSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public ValueCredential(String name) {
    this(new NamedValueSecretData(name));
  }

  public ValueCredential() {
    this(new NamedValueSecretData());
  }

  public static ValueCredential createNewVersion(ValueCredential existing, String name,
                                                 String value, Encryptor encryptor, List<AccessControlEntry> accessControlEntries) {
    ValueCredential secret;

    if (existing == null) {
      secret = new ValueCredential(name);
    } else {
      secret = new ValueCredential();
      secret.copyNameReferenceFrom(existing);
    }

    secret.setAccessControlList(accessControlEntries);
    secret.setEncryptor(encryptor);
    secret.setValue(value);
    return secret;
  }

  public String getValue() {
    return encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()
    );
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
  public String getSecretType() {
    return delegate.getSecretType();
  }


  public void rotate() {
    String decryptedValue = this.getValue();
    this.setValue(decryptedValue);
  }

}
