package io.pivotal.security.generator;

import io.pivotal.security.model.Secret;

public interface SecretGenerator<T, R extends Secret> {
  R generateSecret(T parameters);
}
