package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.StringCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class ValueSetRequest extends BaseCredentialSetRequest<StringCredentialValue> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private StringCredentialValue value;

  public StringCredentialValue getValue() {
    return value;
  }

  public void setValue(StringCredentialValue value) {
    this.value = value;
  }

  @Override
  public StringCredentialValue getCredentialValue() {
    return value;
  }
}
