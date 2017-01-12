package io.pivotal.security.generator;

import io.pivotal.security.view.SecretView;

public interface SecretGenerator<T, R extends SecretView> {
  R generateSecret(T parameters);
}
