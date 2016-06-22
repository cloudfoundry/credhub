package io.pivotal.security.controller.v1;

public class GeneratorRequest<T> {
  private T parameters;
  private String type;

  public T getParameters() {
    return parameters;
  }

  public void setParameters(T parameters) {
    this.parameters = parameters;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }
}
