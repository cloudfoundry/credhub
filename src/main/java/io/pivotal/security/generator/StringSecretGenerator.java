package io.pivotal.security.generator;

import io.pivotal.security.model.StringSecretParameters;

public interface StringSecretGenerator {
  String generateSecret(StringSecretParameters parameters);
}
