package org.cloudfoundry.credhub.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

public class JsonCredentialValue implements CredentialValue {
  @NotEmpty(message = "error.missing_value")
  private final Map<String, Object> value;

  @JsonCreator
  public JsonCredentialValue(Map<String, Object> json) {
    this.value = json;
  }

  @JsonValue
  public Map<String, Object> getValue() {
    return value;
  }
}
