package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UserGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private StringGenerationParameters passwordGenerationParameters = new StringGenerationParameters();

  @JsonProperty("value")
  private UsernameValue value = new UsernameValue();

  @Override
  public void validate() {
    super.validate();
  }

  public StringGenerationParameters getPasswordGenerationParameters() {
    return passwordGenerationParameters;
  }

  public String getUserName() {
    return value.getUsername();
  }

  public void setValue(UsernameValue value) {
    this.value = value;
  }
}
