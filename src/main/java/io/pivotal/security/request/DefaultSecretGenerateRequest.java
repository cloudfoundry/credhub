package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import org.apache.commons.lang.NotImplementedException;

public class DefaultSecretGenerateRequest extends BaseSecretGenerateRequest {
 // @NotNull(message = "error.missing_value")
  private Object value;

  public Object getValue() {
    return value;
  }

  public void setValue(Object value) {
    this.value = value;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    throw new NotImplementedException();
  }
}
