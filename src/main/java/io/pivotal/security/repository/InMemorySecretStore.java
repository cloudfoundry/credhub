package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

// TODO this is no longer necessary
@Component
public class InMemorySecretStore {

  private final InMemorySecretRepository secretRepository;

  @Autowired
  public InMemorySecretStore(InMemorySecretRepository secretRepository) {
    this.secretRepository = secretRepository;
  }

  public void set(NamedSecret secret) {
    secretRepository.save(secret);
  }

  public NamedSecret getSecret(String key) {
    return secretRepository.findOneByName(key);
  }

  public boolean delete(String key) {
    NamedSecret entity = secretRepository.findOneByName(key);
    if (entity != null) {
      secretRepository.delete(entity);
      return true;
    }
    return false;
  }
}
