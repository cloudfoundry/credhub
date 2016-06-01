package io.pivotal.security.model;


public class GeneratorRequest {

  private SecretParameters parameters;
  private String type;

  public SecretParameters getParameters() {
    return parameters;
  }

  public void setParameters(SecretParameters parameters) {
    this.parameters = parameters;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }
}
