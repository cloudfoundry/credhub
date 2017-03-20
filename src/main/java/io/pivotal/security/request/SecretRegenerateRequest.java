package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import org.apache.commons.lang.NotImplementedException;

public class SecretRegenerateRequest extends BaseSecretPostRequest {
  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    throw new NotImplementedException();
  }
}
