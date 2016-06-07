package io.pivotal.security.repository;

import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.StringSecret;

public interface SecretStore {
  void set(String key, StringSecret stringSecret);
  void set(String key, CertificateSecret certificateSecret);

  StringSecret getStringSecret(String key);
  CertificateSecret getCertificateSecret(String key);

  boolean delete(String key);
}
