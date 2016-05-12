package io.pivotal.security.repository;

import io.pivotal.security.entity.Secret;

public interface SecretRepository {
  void set(String key, Secret secret);

  Secret get(String key);

  Secret delete(String key);
}
