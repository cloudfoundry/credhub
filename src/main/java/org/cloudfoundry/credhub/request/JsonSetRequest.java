package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class JsonSetRequest extends BaseCredentialSetRequest<JsonCredentialValue> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private JsonCredentialValue value;

  public JsonCredentialValue getValue() {
    return value;
  }

  public void setValue(JsonCredentialValue value) {
    this.value = value;
  }

  @Override
  public JsonCredentialValue getCredentialValue() {
    return value;
  }
}
