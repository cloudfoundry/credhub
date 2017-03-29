package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.view.SecretKind;
import java.util.List;

public class NamedValueSecret extends NamedSecret<NamedValueSecret> {

  private NamedValueSecretData delegate;

  public NamedValueSecret(NamedValueSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedValueSecret(String name) {
    this(new NamedValueSecretData(name));
  }

  public NamedValueSecret() {
    this(new NamedValueSecretData());
  }

  public static NamedValueSecret createNewVersion(NamedValueSecret existing, String name,
      String value, Encryptor encryptor, List<AccessControlEntry> accessControlEntries) {
    NamedValueSecret secret;

    if (existing == null) {
      secret = new NamedValueSecret(name);
    } else {
      secret = new NamedValueSecret();
      secret.copyNameReferenceFrom(existing);
    }

    secret.setAccessControlList(getAccessEntryData(accessControlEntries, secret));
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

  public NamedValueSecret setValue(String value) {
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

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }

  public void rotate() {
    String decryptedValue = this.getValue();
    this.setValue(decryptedValue);
  }

}
