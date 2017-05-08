package io.pivotal.security.data;

import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.repository.CredentialNameRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CredentialNameDataService {
  private final CredentialNameRepository credentialNameRepository;

  @Autowired
  public CredentialNameDataService(CredentialNameRepository credentialNameRepository) {
    this.credentialNameRepository = credentialNameRepository;
  }

  public CredentialName find(String name) {
    return credentialNameRepository.findOneByNameIgnoreCase(name);
  }

  public CredentialName save(CredentialName credentialName) {
    return credentialNameRepository.saveAndFlush(credentialName);
  }

  public boolean delete(String credentialName) {
    return credentialNameRepository.deleteByNameIgnoreCase(credentialName) > 0;
  }
}
