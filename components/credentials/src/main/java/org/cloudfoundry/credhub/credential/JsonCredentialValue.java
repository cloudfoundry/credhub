package org.cloudfoundry.credhub.credential;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.credhub.ErrorMessages;

@JsonAutoDetect
public class JsonCredentialValue implements CredentialValue {
  @NotNull(message = ErrorMessages.MISSING_VALUE)
  private final JsonNode value;

  @JsonCreator
  public JsonCredentialValue(final JsonNode json) {
    super();
    this.value = json;
  }

  @JsonValue
  public JsonNode getValue() {
    return value;
  }
}
