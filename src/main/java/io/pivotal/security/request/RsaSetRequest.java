package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.RsaCredential;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class RsaSetRequest extends BaseCredentialSetRequest<RsaCredential> {

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
  public RsaCredential createNewVersion(RsaCredential existing, Encryptor encryptor) {
    return RsaCredential
        .createNewVersion(
            existing,
            getName(),
            getKeySetRequestFields(),
            encryptor,
            getAccessControlEntries());
  }
}
