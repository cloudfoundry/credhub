package io.pivotal.security.request;

public class DefaultCredentialGenerateRequest extends BaseCredentialGenerateRequest {

  private Object parameters;

  public Object getParameters() {
    return parameters;
  }

  public void setParameters(Object parameters) {
    this.parameters = parameters;
  }

  @Override
  public GenerationParameters getDomainGenerationParameters() {
    return null;
  }
}
