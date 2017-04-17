package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedRsaSecret;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class RsaSetRequest extends BaseSecretSetRequest<NamedRsaSecret> {

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
  public NamedRsaSecret createNewVersion(NamedRsaSecret existing, Encryptor encryptor) {
    return NamedRsaSecret
        .createNewVersion(
            existing,
            getName(),
            getKeySetRequestFields(),
            encryptor,
            getAccessControlEntries());
  }
}
