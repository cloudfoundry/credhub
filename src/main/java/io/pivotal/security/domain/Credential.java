package io.pivotal.security.domain;

import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.entity.CredentialData;
import io.pivotal.security.entity.CredentialName;
import java.time.Instant;
import java.util.UUID;

public abstract class Credential<Z extends Credential> {

  protected CredentialData delegate;
  protected Encryptor encryptor;

  public Credential(CredentialData delegate) {
    this.delegate = delegate;
  }

  public abstract String getCredentialType();

  public abstract void rotate();

  public UUID getUuid() {
    return delegate.getUuid();
  }

  public Z setUuid(UUID uuid) {
    delegate.setUuid(uuid);
    return (Z) this;
  }

  public String getName() {
    return delegate.getCredentialName().getName();
  }

  public Instant getVersionCreatedAt() {
    return delegate.getVersionCreatedAt();
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    delegate.setVersionCreatedAt(versionCreatedAt);
    return (Z) this;
  }

  public Z setEncryptor(Encryptor encryptor) {
    this.encryptor = encryptor;
    return (Z) this;
  }

  public <Z extends Credential> Z save(CredentialDataService credentialDataService) {
    return (Z) credentialDataService.save(delegate);
  }

  public CredentialName getCredentialName() {
    return delegate.getCredentialName();
  }

  protected void copyNameReferenceFrom(Credential credential) {
    this.delegate.setCredentialName(credential.delegate.getCredentialName());
  }

}
