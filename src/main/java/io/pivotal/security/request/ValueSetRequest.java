package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
import org.hibernate.validator.constraints.NotEmpty;

public class ValueSetRequest extends BaseSecretSetRequest {
  @NotEmpty(message = "error.missing_value")
  private String value;

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    return NamedValueSecret.createNewVersion((NamedValueSecret) existing, getName(), this.getValue(), encryptor, this.getAccessControlEntries());
  }
}
