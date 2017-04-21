package io.pivotal.security.generator;

import io.pivotal.security.credential.CredentialValue;

public interface CredentialGenerator<T, R extends CredentialValue> {

  R generateCredential(T parameters);
}
