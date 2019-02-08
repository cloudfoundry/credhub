package org.cloudfoundry.credhub.requests;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SshGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private SshGenerationParameters generationParameters;

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new SshGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(final SshGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }
}
