package io.pivotal.security.generator;

import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.request.BaseCredentialGenerateRequest;

public interface CredentialGenerator<T, R extends CredentialValue> {

  R generateCredential(T parameters);

  R generateCredential(BaseCredentialGenerateRequest requestBody);
}
