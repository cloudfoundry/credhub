package io.pivotal.security.domain;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.EncryptedValueContainer;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.view.SecretKind;

import java.time.Instant;
import java.util.UUID;

public abstract class NamedSecret<Z extends NamedSecret>  implements EncryptedValueContainer {
  protected NamedSecretData delegate;
  protected Encryptor encryptor;

  public abstract SecretKind getKind();
  public abstract String getSecretType();
  public abstract void rotate();

  public NamedSecret(NamedSecretData delegate) {
    this.delegate = delegate;
  }

  public UUID getUuid() {
    return delegate.getUuid();
  }

  public Z setUuid(UUID uuid) {
    delegate.setUuid(uuid);
    return (Z) this;
  }

  public String getName() {
    return delegate.getSecretName().getName();
  }

  public byte[] getEncryptedValue() {
    return delegate.getEncryptedValue();
  }

  public void setEncryptedValue(byte[] encryptedValue) {
    delegate.setEncryptedValue(encryptedValue);
  }

  public byte[] getNonce() {
    return delegate.getNonce();
  }

  public void setNonce(byte[] nonce) {
    delegate.setNonce(nonce);
  }

  public UUID getEncryptionKeyUuid() {
    return delegate.getEncryptionKeyUuid();
  }

  public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    delegate.setEncryptionKeyUuid(encryptionKeyUuid);
  }

  public Instant getVersionCreatedAt() {
    return  delegate.getVersionCreatedAt();
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    delegate.setVersionCreatedAt(versionCreatedAt);
    return (Z) this;
  }

  public void copyInto(Z copy) {
    copy.encryptor = this.encryptor;
    delegate.copyInto(copy.delegate);
  }

  public Z setEncryptor(Encryptor encryptor) {
    this.encryptor = encryptor;
    return (Z) this;
  }

  public <Z extends NamedSecret> Z save(SecretDataService secretDataService) {
    return (Z) secretDataService.save(delegate);
  }
}
