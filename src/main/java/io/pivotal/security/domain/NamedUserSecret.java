package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedUserSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.UserSetRequestFields;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class NamedUserSecret extends NamedSecret<NamedUserSecret> {
  private final NamedUserSecretData delegate;

  public static NamedUserSecret createNewVersion(
      NamedUserSecret existing,
      String name,
      UserSetRequestFields fields,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries) {
    NamedUserSecret secret;
    if (existing == null) {
      secret = new NamedUserSecret(name);
    } else {
      secret = new NamedUserSecret();
      secret.copyNameReferenceFrom(existing);
    }

    secret.setEncryptor(encryptor);

    secret.setUsername(fields.getUsername());
    secret.setPassword(fields.getPassword());

    secret.setAccessControlList(accessControlEntries);

    return secret;
  }

  public NamedUserSecret() {
    this(new NamedUserSecretData());
  }

  public NamedUserSecret(NamedUserSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedUserSecret(String name) {
    this(new NamedUserSecretData(name));
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  public void rotate() {
    String decryptedPassword = getPassword();
    setPassword(decryptedPassword);
  }

  public NamedUserSecret setPassword(String password) {
    Encryption passwordEncryption = encryptor.encrypt(password);
    delegate.setEncryptionKeyUuid(passwordEncryption.canaryUuid);
    delegate.setEncryptedValue(passwordEncryption.encryptedValue);
    delegate.setNonce(passwordEncryption.nonce);
    return this;
  }

  public String getPassword() {
    return encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce());
  }

  public NamedUserSecret setUsername(String username) {
    delegate.setUsername(username);
    return this;
  }

  public String getUsername() {
    return delegate.getUsername();
  }
}
