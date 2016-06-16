package io.pivotal.security.repository;

import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.Secret;
import io.pivotal.security.model.StringSecret;

public interface SecretStore {
  void set(String key, Secret Secret);

  Secret getSecret(String key);

  boolean delete(String key);
}
