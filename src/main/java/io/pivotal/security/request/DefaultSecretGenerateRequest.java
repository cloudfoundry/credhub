package io.pivotal.security.request;

import io.pivotal.security.service.GeneratorService;

public class DefaultSecretGenerateRequest extends BaseSecretGenerateRequest {

  private Object parameters;

  public Object getParameters() {
    return parameters;
  }

  public void setParameters(Object parameters) {
    this.parameters = parameters;
  }

  @Override
  public BaseSecretSetRequest createSetRequest(GeneratorService generatorService) {
    return null;
  }
}
