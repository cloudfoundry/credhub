package org.cloudfoundry.credhub.request;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;

public class JsonSetRequest extends BaseCredentialSetRequest<JsonCredentialValue> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private JsonCredentialValue value;

  public JsonCredentialValue getValue() {
    return value;
  }

  public void setValue(final JsonCredentialValue value) {
    this.value = value;
  }

  @Override
  public JsonCredentialValue getCredentialValue() {
    return value;
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
