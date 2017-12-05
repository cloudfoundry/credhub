package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.StringCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

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

  public void setPassword(StringCredentialValue password) {
    this.password = password;
  }

  public void setGenerationParameters(StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  public StringGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  @Override
  public StringCredentialValue getCredentialValue() {
    return password;
  }
}
