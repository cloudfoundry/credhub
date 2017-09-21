package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PasswordGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private StringGenerationParameters generationParameters;

  public StringGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new StringGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public GenerationParameters getDomainGenerationParameters() {
    return generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

}
