package org.cloudfoundry.credhub.requests;

import java.util.Objects;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;

public class RsaSetRequest extends BaseCredentialSetRequest<RsaCredentialValue> {

  @NotNull(message = ErrorMessages.MISSING_VALUE)
  @Valid
  @JsonProperty("value")
  private RsaCredentialValue rsaKeyValue;

  public RsaCredentialValue getRsaKeyValue() {
    return rsaKeyValue;
  }

  public void setRsaKeyValue(final RsaCredentialValue rsaKeyValue) {
    this.rsaKeyValue = rsaKeyValue;
  }

  @Override
  public RsaCredentialValue getCredentialValue() {
    return rsaKeyValue;
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final RsaSetRequest that = (RsaSetRequest) o;
    return Objects.equals(rsaKeyValue, that.rsaKeyValue);
  }

  @Override
  public int hashCode() {
    return Objects.hash(rsaKeyValue);
  }
}
