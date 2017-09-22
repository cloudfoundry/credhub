package io.pivotal.security.generator;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.request.GenerationParameters;

public interface CredentialGenerator<R extends CredentialValue> {
  R generateCredential(GenerationParameters parameters, UserContext userContext);
}
