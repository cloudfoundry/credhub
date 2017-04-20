package io.pivotal.security.generator;

import io.pivotal.security.credential.Credential;

public interface CredentialGenerator<T, R extends Credential> {

  R generateSecret(T parameters);
}
