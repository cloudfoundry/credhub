package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.model.StringSecret;
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
  public void set(String key, StringSecret stringSecret) {
    NamedStringSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret == null) {
      namedStringSecret = new NamedStringSecret();
      namedStringSecret.name = key;
    }
    namedStringSecret.value = stringSecret.value;
    secretRepository.save(namedStringSecret);
  }

  @Override
  public StringSecret get(String key) {
    NamedStringSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret != null) {
      return StringSecret.make(namedStringSecret.value);
    }
    return null;
  }

  @Transactional
  @Override
  public boolean delete(String key) {
    NamedStringSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret != null) {
      secretRepository.delete(namedStringSecret);
      return true;
    }
    return false;
  }
}
