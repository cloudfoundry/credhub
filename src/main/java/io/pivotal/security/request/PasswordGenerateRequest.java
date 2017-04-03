package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.service.GeneratorService;

import java.util.List;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest {

  public static final List<AccessControlEntry> NULL_ACCESS_CONTROL_ENTRIES = null;
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
    passwordSetRequest.setAccessControlEntries(NULL_ACCESS_CONTROL_ENTRIES);

    return passwordSetRequest;
  }
}
