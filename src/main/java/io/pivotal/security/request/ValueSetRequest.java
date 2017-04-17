package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedValueSecret;
import org.hibernate.validator.constraints.NotEmpty;

public class ValueSetRequest extends BaseSecretSetRequest<NamedValueSecret> {

  @NotEmpty(message = "error.missing_value")
  private String value;

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public NamedValueSecret createNewVersion(NamedValueSecret existing, Encryptor encryptor) {
    return NamedValueSecret
        .createNewVersion(existing, getName(), this.getValue(), encryptor,
            this.getAccessControlEntries());
  }
}
