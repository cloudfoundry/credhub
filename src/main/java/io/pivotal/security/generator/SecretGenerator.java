package io.pivotal.security.generator;

import io.pivotal.security.view.Secret;

public interface SecretGenerator<T, R extends Secret> {
  R generateSecret(T parameters);
}
