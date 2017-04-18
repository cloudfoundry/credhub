package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.service.GeneratorService;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest {

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
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    PasswordSetRequest passwordSetRequest = new PasswordSetRequest();
    passwordSetRequest.setGenerationParameters(getGenerationParameters());
    passwordSetRequest.setType(getType());
    passwordSetRequest.setName(getName());
    passwordSetRequest.setOverwrite(isOverwrite());
    passwordSetRequest.setAccessControlEntries(getAccessControlEntries());

    passwordSetRequest.setPassword(generatorService.generatePassword(getGenerationParameters()));

    return passwordSetRequest;
  }
}
