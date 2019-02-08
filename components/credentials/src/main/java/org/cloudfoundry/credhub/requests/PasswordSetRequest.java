package org.cloudfoundry.credhub.requests;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.StringCredentialValue;

public class PasswordSetRequest extends BaseCredentialSetRequest<StringCredentialValue> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private StringCredentialValue password;
  @JsonIgnore
  private StringGenerationParameters generationParameters;

  public StringCredentialValue getPassword() {
    return password;
  }

  public void setPassword(final StringCredentialValue password) {
    this.password = password;
  }

  @Override
  public StringGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  public void setGenerationParameters(final StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public StringCredentialValue getCredentialValue() {
    return password;
  }
}
