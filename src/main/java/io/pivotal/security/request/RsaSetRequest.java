package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.RsaKey;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.RsaCredential;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class RsaSetRequest extends BaseCredentialSetRequest<RsaCredential> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private RsaKey rsaKeyValue;

  public RsaKey getRsaKeyValue() {
    return rsaKeyValue;
  }

  public void setRsaKeyValue(RsaKey rsaKeyValue) {
    this.rsaKeyValue = rsaKeyValue;
  }

  @Override
  public RsaCredential createNewVersion(RsaCredential existing, Encryptor encryptor) {
    return RsaCredential
        .createNewVersion(
            existing,
            getName(),
            getRsaKeyValue(),
            encryptor,
            getAccessControlEntries());
  }
}
