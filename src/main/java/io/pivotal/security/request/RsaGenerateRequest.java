package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RsaGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private RsaGenerationParameters generationParameters;

  public RsaGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new RsaGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(RsaGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }
}
