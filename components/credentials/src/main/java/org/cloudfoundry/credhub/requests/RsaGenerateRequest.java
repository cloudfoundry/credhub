package org.cloudfoundry.credhub.requests;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class RsaGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private RsaGenerationParameters generationParameters;

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new RsaGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(final RsaGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }
}
