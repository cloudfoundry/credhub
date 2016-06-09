package io.pivotal.security.generator;

import io.pivotal.security.model.SecretParameters;

public interface StringSecretGenerator {
  String generateSecret(SecretParameters parameters);
}
