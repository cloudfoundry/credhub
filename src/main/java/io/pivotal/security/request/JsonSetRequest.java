package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedJsonSecret;
import io.pivotal.security.domain.NamedSecret;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

public class JsonSetRequest extends BaseSecretSetRequest {
  @NotEmpty(message = "error.missing_value")
  private Map<String, Object> value;

  public Map<String, Object> getValue() {
    return value;
  }

  public void setValue(Map<String, Object> value) {
    this.value = value;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    return NamedJsonSecret.createNewVersion((NamedJsonSecret) existing, getName(), this.getValue(), encryptor, this.getAccessControlEntries());
  }
}
