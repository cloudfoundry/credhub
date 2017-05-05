package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.ValueCredential;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class ValueSetRequest extends BaseCredentialSetRequest<ValueCredential> {

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
  public ValueCredential createNewVersion(ValueCredential existing, Encryptor encryptor) {
    return ValueCredential
        .createNewVersion(
            existing,
            getName(),
            getValue().getStringCredential(),
            encryptor);
  }
}
