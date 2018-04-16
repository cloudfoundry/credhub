package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class CertificateDataService {
  private final CredentialRepository credentialRepository;
  private CEFAuditRecord auditRecord;

  @Autowired
  public CertificateDataService(CredentialRepository credentialRepository,
      CEFAuditRecord auditRecord) {
    this.credentialRepository = credentialRepository;
    this.auditRecord = auditRecord;
  }

  public List<Credential> findAll() {
    return credentialRepository.findAllCertificates();
  }

  public Credential findByName(String name) {
    Credential credential = credentialRepository.findCertificateByName(name);
    auditRecord.setResource(credential);
    return credential;
  }

  public Credential findByUuid(UUID uuid) {
    return credentialRepository.findCertificateByUuid(uuid);
  }
}
