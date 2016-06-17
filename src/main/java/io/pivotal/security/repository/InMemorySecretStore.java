package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.model.Secret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class InMemorySecretStore implements SecretStore {

  private final InMemorySecretRepository secretRepository;

  @Autowired
  public InMemorySecretStore(InMemorySecretRepository secretRepository) {
    this.secretRepository = secretRepository;
  }

  @Override
  public void set(String key, Secret secret) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret == null) {
      namedSecret = secret.makeEntity(key);
    }
    secret.populateEntity(namedSecret);
    secretRepository.save(namedSecret);
  }

  @Override
  public Secret getSecret(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      return namedSecret.convertToModel();
    }
    return null;
  }

  @Override
  public boolean delete(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      secretRepository.delete(namedSecret);
      return true;
    }
    return false;
  }
}
