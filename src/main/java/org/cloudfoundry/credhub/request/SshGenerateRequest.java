package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SshGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private SshGenerationParameters generationParameters;

  public void setGenerationParameters(SshGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new SshGenerationParameters();
    }
    return generationParameters;
  }
}
