package org.cloudfoundry.credhub.services;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repositories.CredentialRepository;

@Service
public class CredentialDataService {

  private final CredentialRepository credentialRepository;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public CredentialDataService(final CredentialRepository credentialRepository, final CEFAuditRecord auditRecord) {
    super();
    this.credentialRepository = credentialRepository;
    this.auditRecord = auditRecord;
  }

  public Credential find(final String name) {
    return credentialRepository.findOneByNameIgnoreCase(name);
  }

  public Credential findByUUID(final UUID uuid) {
    return credentialRepository.findOneByUuid(uuid);
  }

  public Credential save(final Credential credential) {
    return credentialRepository.saveAndFlush(credential);
  }

  public boolean delete(final String credentialName) {
    final Credential cred = this.find(credentialName);
    auditRecord.setResource(cred);
    return credentialRepository.deleteByNameIgnoreCase(credentialName) > 0;
  }

}
