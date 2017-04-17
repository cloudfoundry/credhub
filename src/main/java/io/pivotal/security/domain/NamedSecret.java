package io.pivotal.security.domain;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.request.AccessControlEntry;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public abstract class NamedSecret<Z extends NamedSecret> {

  protected NamedSecretData delegate;
  protected Encryptor encryptor;

  public NamedSecret(NamedSecretData delegate) {
    this.delegate = delegate;
  }

  public abstract String getSecretType();

  public abstract void rotate();

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

  public <Z extends NamedSecret> Z save(SecretDataService secretDataService) {
    return (Z) secretDataService.save(delegate);
  }

  public void setAccessControlList(List<AccessControlEntry> accessControlEntries) {
    List<AccessEntryData> accessEntryData = this.getAccessEntryData(accessControlEntries);
    delegate.getSecretName().setAccessControlList(accessEntryData);
  }

  public SecretName getSecretName() {
    return delegate.getSecretName();
  }

  public boolean isVersionOfSameSecret(NamedSecret otherSecret) {
    return delegate.getSecretName().equals(otherSecret.delegate.getSecretName());
  }

  protected void copyNameReferenceFrom(NamedSecret namedSecret) {
    this.delegate.setSecretName(namedSecret.delegate.getSecretName());
  }

  List<AccessEntryData> getAccessEntryData(List<AccessControlEntry> accessControlEntries) {
    SecretName secretName = delegate.getSecretName();
    return accessControlEntries.stream()
        .map((entry) -> AccessEntryData.fromSecretName(secretName, entry))
        .collect(Collectors.toList());
  }
}
