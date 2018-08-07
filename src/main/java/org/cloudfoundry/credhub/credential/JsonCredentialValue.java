package org.cloudfoundry.credhub.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.JsonNode;

import javax.validation.constraints.NotNull;

@JsonAutoDetect
public class JsonCredentialValue implements CredentialValue {
  @NotNull(message = "error.missing_value")
  private final JsonNode value;

  @JsonCreator
  public JsonCredentialValue(JsonNode json) {
    this.value = json;
  }

  @JsonValue
  public JsonNode getValue() {
    return value;
  }
}
