package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SshGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private SshGenerationParameters generationParameters;

  public SshGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new SshGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(SshGenerationParameters generationParameters) {
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
