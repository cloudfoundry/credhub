package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateBody {
  @JsonProperty("ca")
  private String ca;
  @JsonProperty("public")
  private String certificate;
  @JsonProperty("private")
  private String privateKey;

  public CertificateBody(String ca, String certificate, String privateKey) {
    this.setCa(ca);
    this.setCertificate(certificate);
    this.setPrivateKey(privateKey);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getCertificate() {
    return certificate;
  }

  public void setCertificate(String certificate) {
    this.certificate = certificate;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
  }
}
