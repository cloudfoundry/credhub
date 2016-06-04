package io.pivotal.security.repository;

import io.pivotal.security.model.StringSecret;

public interface SecretStore {
  void set(String key, StringSecret stringSecret);

  StringSecret get(String key);

  StringSecret delete(String key);
}
