package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class CredentialDataService {

  private final CredentialRepository credentialRepository;
  private CEFAuditRecord auditRecord;

  @Autowired
  public CredentialDataService(CredentialRepository credentialRepository, CEFAuditRecord auditRecord) {
    this.credentialRepository = credentialRepository;
    this.auditRecord = auditRecord;
  }

  public Credential find(String name) {
    Credential credential = credentialRepository.findOneByNameIgnoreCase(name);
    return credential;
  }

  public Credential findByUUID(UUID uuid) {
    Credential credential = credentialRepository.findOneByUuid(uuid);
    return credential;
  }

  public Credential save(Credential credential) {
    return credentialRepository.saveAndFlush(credential);
  }

  public boolean delete(String credentialName) {
    Credential cred = this.find(credentialName);
    auditRecord.setResource(cred);
    return credentialRepository.deleteByNameIgnoreCase(credentialName) > 0;
  }

  public List<Credential> findAll() {
    return credentialRepository.findAll();
  }
}
