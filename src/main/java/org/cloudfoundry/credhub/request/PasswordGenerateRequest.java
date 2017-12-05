package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class PasswordGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private StringGenerationParameters generationParameters;

  public void setGenerationParameters(StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new StringGenerationParameters();
    }
    return generationParameters;
  }
}
