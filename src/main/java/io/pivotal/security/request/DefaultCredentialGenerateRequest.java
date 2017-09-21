package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class DefaultCredentialGenerateRequest extends BaseCredentialGenerateRequest {

  private Object parameters;

  public Object getParameters() {
    return parameters;
  }

  public void setParameters(Object parameters) {
    this.parameters = parameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getDomainGenerationParameters() {
    return null;
  }
}
