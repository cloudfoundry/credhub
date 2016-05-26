package io.pivotal.security.generator;

import io.pivotal.security.model.SecretParameters;

public interface SecretGenerator {
  String generateSecret(SecretParameters parameters);
}
