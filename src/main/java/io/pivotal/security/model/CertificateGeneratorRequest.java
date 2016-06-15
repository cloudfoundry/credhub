package io.pivotal.security.model;


public class CertificateGeneratorRequest {
  private CertificateSecretParameters parameters;
  private String type;

  public CertificateSecretParameters getParameters() {
    return parameters;
  }

  public void setParameters(CertificateSecretParameters parameters) {
    this.parameters = parameters;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }
}