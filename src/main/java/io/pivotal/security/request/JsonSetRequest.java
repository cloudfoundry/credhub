package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.JsonCredential;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class JsonSetRequest extends BaseCredentialSetRequest<JsonCredential, JsonCredentialValue> {

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
  @JsonIgnore
  public JsonCredential createNewVersion(JsonCredential existing, Encryptor encryptor) {
    return JsonCredential.createNewVersion(
        existing,
        getName(),
        getValue().getValue(),
        encryptor
    );
  }

  @Override
  public JsonCredentialValue getCredentialValue() {
    return value;
  }
}
