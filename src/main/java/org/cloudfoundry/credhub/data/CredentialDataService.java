package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class CredentialDataService {

  private final CredentialRepository credentialRepository;

  @Autowired
  public CredentialDataService(CredentialRepository credentialRepository) {
    this.credentialRepository = credentialRepository;
  }

  public Credential find(String name) {
    return credentialRepository.findOneByNameIgnoreCase(name);
  }

  public Credential findByUUID(UUID uuid) {
    return credentialRepository.findOneByUuid(uuid);
  }

  public Credential save(Credential credential) {
    return credentialRepository.saveAndFlush(credential);
  }

  public boolean delete(String credentialName) {
    return credentialRepository.deleteByNameIgnoreCase(credentialName) > 0;
  }

  public List<Credential> findAll() {
    return credentialRepository.findAll();
  }
}
