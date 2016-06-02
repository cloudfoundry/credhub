package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.model.Secret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class InMemorySecretStore implements SecretStore {

  private final InMemorySecretRepository secretRepository;

  @Autowired
  public InMemorySecretStore(InMemorySecretRepository secretRepository) {
    this.secretRepository = secretRepository;
  }

  @Transactional
  @Override
  public void set(String key, Secret secret) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret == null) {
      namedSecret = new NamedSecret();
      namedSecret.name = key;
    }
    namedSecret.type = secret.type;
    namedSecret.value = secret.value;
    secretRepository.save(namedSecret);
  }

  @Override
  public Secret get(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      return Secret.make(namedSecret.value, namedSecret.type);
    }
    return null;
  }

  @Transactional
  @Override
  public Secret delete(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      secretRepository.delete(namedSecret);
      return Secret.make(namedSecret.value, namedSecret.type);
    }
    return null;
  }
}
