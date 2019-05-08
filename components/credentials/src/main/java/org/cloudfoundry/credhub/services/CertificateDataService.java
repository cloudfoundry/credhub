package org.cloudfoundry.credhub.services;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repositories.CredentialRepository;

@Service
public class CertificateDataService {
  private final CredentialRepository credentialRepository;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public CertificateDataService(final CredentialRepository credentialRepository,
                                final CEFAuditRecord auditRecord) {
    super();
    this.credentialRepository = credentialRepository;
    this.auditRecord = auditRecord;
  }

  public List<Credential> findAll() {
    return credentialRepository.findAllCertificates();
  }

  public Credential findByName(final String name) {
    final Credential credential = credentialRepository.findCertificateByName(name);
    auditRecord.setResource(credential);
    return credential;
  }

  public Credential findByUuid(final UUID uuid) {
    return credentialRepository.findCertificateByUuid(uuid);
  }
}
