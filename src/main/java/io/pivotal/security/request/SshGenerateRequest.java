package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.service.GeneratorService;

public class SshGenerateRequest extends BaseSecretGenerateRequest {

  @JsonProperty("parameters")
  private SshGenerationParameters generationParameters;

  public SshGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new SshGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(SshGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    SshSetRequest sshSetRequest = new SshSetRequest();
    SshKey sshKeys = generatorService.generateSshKeys(getGenerationParameters());
    sshSetRequest.setKeySetRequestFields(new KeySetRequestFields(sshKeys.getPrivateKey(), sshKeys.getPublicKey()));
    sshSetRequest.setType(getType());
    sshSetRequest.setName(getName());
    sshSetRequest.setOverwrite(isOverwrite());
    sshSetRequest.setAccessControlEntries(getAccessControlEntries());

    return sshSetRequest;
  }
}
