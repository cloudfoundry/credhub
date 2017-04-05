package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.service.GeneratorService;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest {

  @JsonProperty("parameters")
  private PasswordGenerationParameters generationParameters;

  public PasswordGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new PasswordGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(PasswordGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    PasswordSetRequest passwordSetRequest = new PasswordSetRequest();
    passwordSetRequest.setPassword(generatorService.generatePassword(getGenerationParameters()));
    passwordSetRequest.setGenerationParameters(getGenerationParameters());
    passwordSetRequest.setType(getType());
    passwordSetRequest.setName(getName());
    passwordSetRequest.setOverwrite(isOverwrite());
    passwordSetRequest.setAccessControlEntries(getAccessControlEntries());

    return passwordSetRequest;
  }
}
