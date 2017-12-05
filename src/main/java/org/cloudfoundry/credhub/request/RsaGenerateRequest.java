package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class RsaGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private RsaGenerationParameters generationParameters;

  public void setGenerationParameters(RsaGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new RsaGenerationParameters();
    }
    return generationParameters;
  }
}
