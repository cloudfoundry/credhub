package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.service.GeneratorService;

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

  public BaseCredentialSetRequest generateSetRequest(GeneratorService generatorService) {
    RsaSetRequest rsaSetRequest = new RsaSetRequest();
    RsaCredentialValue rsaKey = generatorService.generateRsaKeys(getGenerationParameters());
    rsaSetRequest.setRsaKeyValue(rsaKey);
    rsaSetRequest.setType(getType());
    rsaSetRequest.setName(getName());
    rsaSetRequest.setOverwrite(isOverwrite());
    rsaSetRequest.setAccessControlEntries(getAccessControlEntries());

    return rsaSetRequest;
  }
}
