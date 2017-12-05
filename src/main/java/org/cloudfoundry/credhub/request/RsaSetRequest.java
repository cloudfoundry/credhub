package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class RsaSetRequest extends BaseCredentialSetRequest<RsaCredentialValue> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private RsaCredentialValue rsaKeyValue;

  public RsaCredentialValue getRsaKeyValue() {
    return rsaKeyValue;
  }

  public void setRsaKeyValue(RsaCredentialValue rsaKeyValue) {
    this.rsaKeyValue = rsaKeyValue;
  }

  @Override
  public RsaCredentialValue getCredentialValue() {
    return rsaKeyValue;
  }
}
