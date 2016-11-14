package io.pivotal.security.controller.v1;

public class CaGenerateRequestBody {
  private String name;
  private String type;
  private CaGenerateParametersRequestBody parameters;

  public CaGenerateRequestBody() {
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public CaGenerateParametersRequestBody getParameters() {
    return parameters;
  }

  public void setParameters(CaGenerateParametersRequestBody parameters) {
    this.parameters = parameters;
  }
}
