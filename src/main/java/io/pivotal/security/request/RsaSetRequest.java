package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.generator.SecretGenerator;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class RsaSetRequest extends BaseSecretSetRequest {
  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private KeySetRequestFields keySetRequestFields;

  public KeySetRequestFields getKeySetRequestFields() {
    return keySetRequestFields;
  }

  public void setKeySetRequestFields(KeySetRequestFields keySetRequestFields) {
    this.keySetRequestFields = keySetRequestFields;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor, SecretGenerator secretGenerator) {
    return NamedRsaSecret.createNewVersion((NamedRsaSecret) existing, getName(), this.getKeySetRequestFields(), encryptor, this.getAccessControlEntries());
  }
}
