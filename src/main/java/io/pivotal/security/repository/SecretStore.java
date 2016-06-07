package io.pivotal.security.repository;

import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.Secret;
import io.pivotal.security.model.StringSecret;

public interface SecretStore {
  void set(String key, StringSecret stringSecret);
  void set(String key, CertificateSecret certificateSecret);

  Secret getSecret(String key);

  boolean delete(String key);
}
