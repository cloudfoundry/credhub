package io.pivotal.security.controller.v1;

public class CaGenerateParametersRequestBody {
  private String common_name;

  public CaGenerateParametersRequestBody() {
  }

  public void setCommon_name(String common_name) {
    this.common_name = common_name;
  }

  public CaGenerateParametersRequestBody(String common_name) {

    this.common_name = common_name;
  }
}
