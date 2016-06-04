package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedStringSecret;
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
    NamedStringSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret == null) {
      namedStringSecret = new NamedStringSecret();
      namedStringSecret.name = key;
    }
    namedStringSecret.value = secret.value;
    secretRepository.save(namedStringSecret);
  }

  @Override
  public Secret get(String key) {
    NamedStringSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret != null) {
      return Secret.make("value", namedStringSecret.value);
    }
    return null;
  }

  @Transactional
  @Override
  public Secret delete(String key) {
    NamedStringSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret != null) {
      secretRepository.delete(namedStringSecret);
      return Secret.make("value", namedStringSecret.value);
    }
    return null;
  }
}
