package io.pivotal.security.generator;

import io.pivotal.security.secret.Secret;

public interface SecretGenerator<T, R extends Secret> {

  R generateSecret(T parameters);
}
