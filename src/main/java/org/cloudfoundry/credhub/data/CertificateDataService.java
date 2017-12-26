package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class CertificateDataService {
  private final CredentialRepository credentialRepository;

  @Autowired
  public CertificateDataService(CredentialRepository credentialRepository) {
    this.credentialRepository = credentialRepository;
  }

  public List<Credential> findAll() {
    return credentialRepository.findAllCertificates();
  }

  public Credential findByName(String name) {
    return credentialRepository.findCertificateByName(name);
  }

  public Credential findByUuid(UUID uuid) {
    return credentialRepository.findCertificateByUuid(uuid);
  }
}
