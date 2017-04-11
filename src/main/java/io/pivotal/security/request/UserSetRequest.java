package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;

public class UserSetRequest extends BaseSecretSetRequest {
  private Object value;

  public void setValue(Object value) {
    this.value = value;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    return null;
  }
}
