package io.pivotal.security.repository;

import io.pivotal.security.model.Secret;

public interface SecretStore {
  void set(String key, Secret secret);

  Secret get(String key);

  Secret delete(String key);
}
