package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SecretRegenerateRequest extends BaseSecretPostRequest {
  @Override
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    throw new NotImplementedException();
  }
}
