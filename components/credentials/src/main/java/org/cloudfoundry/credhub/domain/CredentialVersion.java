package org.cloudfoundry.credhub.domain;

import java.time.Instant;
import java.util.UUID;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.audit.AuditableCredentialVersion;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;

public abstract class CredentialVersion implements AuditableCredentialVersion {

  protected CredentialVersionData delegate;
  protected Encryptor encryptor;

  public CredentialVersion(final CredentialVersionData delegate) {
    super();
    this.delegate = delegate;
  }

  public abstract String getCredentialType();

  public abstract void rotate();

  public Object getValue() {
    return encryptor.decrypt(delegate.getEncryptedValueData());
  }

  public void setValue(final String value) {
    final EncryptedValue encryption = encryptor.encrypt(value);
    delegate.setEncryptedValueData(encryption);
  }

  @Override
  public UUID getUuid() {
    return delegate.getUuid();
  }

  @Override
  public void setUuid(final UUID uuid) {
    delegate.setUuid(uuid);
  }

  @SuppressFBWarnings
  public String getName() {
    return delegate.getCredential().getName();
  }

  public Instant getVersionCreatedAt() {
    return delegate.getVersionCreatedAt();
  }

  public void setVersionCreatedAt(final Instant versionCreatedAt) {
    delegate.setVersionCreatedAt(versionCreatedAt);
  }

  public void setEncryptor(final Encryptor encryptor) {
    this.encryptor = encryptor;
  }

  public <Z extends CredentialVersion> Z save(final CredentialVersionDataService credentialVersionDataService) {
    return (Z) credentialVersionDataService.save(delegate);
  }

  public Credential getCredential() {
    return delegate.getCredential();
  }

  public void setCredential(final Credential credential) {
    this.delegate.setCredential(credential);
  }

  protected void copyNameReferenceFrom(final CredentialVersion credentialVersion) {
    this.delegate.setCredential(credentialVersion.delegate.getCredential());
  }

  public void createName(final String name) {
    delegate.setCredential(new Credential(name));
  }

  public abstract GenerationParameters getGenerationParameters();

  public abstract boolean matchesGenerationParameters(GenerationParameters generationParameters);
}
