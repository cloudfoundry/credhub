package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateBody {
  @JsonProperty("ca")
  private String ca;
  @JsonProperty("certificate")
  private String certificate;
  @JsonProperty("private_key")
  private String privateKey;

  public CertificateBody(String root, String certificate, String privateKey) {
    this.setCa(root);
    this.setCertificate(certificate);
    this.setPrivateKey(privateKey);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String root) {
    this.ca = root;
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
