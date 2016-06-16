package io.pivotal.security.generator;

import io.pivotal.security.model.Secret;

public interface SecretGenerator<T> {  // TODO genericize return type
  Secret generateSecret(T parameters);
}
