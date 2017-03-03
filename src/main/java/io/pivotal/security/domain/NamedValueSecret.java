package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.view.SecretKind;

import static org.apache.commons.lang3.StringUtils.prependIfMissing;

public class NamedValueSecret extends NamedSecret<NamedValueSecret> {
  private NamedValueSecretData delegate;

  public static NamedValueSecret createNewVersion(NamedValueSecret existing, String name, String value, Encryptor encryptor) {
    if (existing != null) {
      return existing.createNewVersion(value);
    } else {
      NamedValueSecret secret = new NamedValueSecret(name);
      secret.setEncryptor(encryptor);
      secret.setValue(value);
      return secret;
    }
  }

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
    delegate.setEncryptionKeyUuid(encryptor.getActiveUuid());

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

  public void rotate(){
    String decryptedValue = this.getValue();
    this.setValue(decryptedValue);
  }

  public NamedValueSecret createNewVersion(String value) {
    NamedValueSecret secret = new NamedValueSecret();
    secret.setEncryptor(encryptor);
    secret.setValue(value);
    secret.delegate.setSecretName(this.delegate.getSecretName());
    return secret;
  }
}
