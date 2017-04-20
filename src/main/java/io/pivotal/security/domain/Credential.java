package io.pivotal.security.domain;

import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.request.AccessControlEntry;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public abstract class Credential<Z extends Credential> {

  protected NamedSecretData delegate;
  protected Encryptor encryptor;

  public Credential(NamedSecretData delegate) {
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

  public void setAccessControlList(List<AccessControlEntry> accessControlEntries) {
    List<AccessEntryData> accessEntryData = this.getAccessEntryData(accessControlEntries);
    delegate.getCredentialName().setAccessControlList(accessEntryData);
  }

  public CredentialName getCredentialName() {
    return delegate.getCredentialName();
  }

  protected void copyNameReferenceFrom(Credential credential) {
    this.delegate.setCredentialName(credential.delegate.getCredentialName());
  }

  List<AccessEntryData> getAccessEntryData(List<AccessControlEntry> accessControlEntries) {
    CredentialName credentialName = delegate.getCredentialName();
    return accessControlEntries.stream()
        .map((entry) -> AccessEntryData.fromCredentialName(credentialName, entry))
        .collect(Collectors.toList());
  }
}
