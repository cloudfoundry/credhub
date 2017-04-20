package io.pivotal.security.request;

import io.pivotal.security.service.GeneratorService;

public class DefaultCredentialGenerateRequest extends BaseCredentialGenerateRequest {

  private Object parameters;

  public Object getParameters() {
    return parameters;
  }

  public void setParameters(Object parameters) {
    this.parameters = parameters;
  }

  @Override
  public BaseCredentialSetRequest generateSetRequest(GeneratorService generatorService) {
    return null;
  }
}
