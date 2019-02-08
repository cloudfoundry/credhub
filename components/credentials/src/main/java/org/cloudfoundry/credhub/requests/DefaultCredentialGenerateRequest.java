package org.cloudfoundry.credhub.requests;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class DefaultCredentialGenerateRequest extends BaseCredentialGenerateRequest {

  private Object parameters;

  public Object getParameters() {
    return parameters;
  }

  public void setParameters(final Object parameters) {
    this.parameters = parameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
