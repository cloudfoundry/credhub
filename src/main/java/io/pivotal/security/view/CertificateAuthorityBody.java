package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateAuthorityBody {
  @JsonProperty("certificate")
  private String certificate;
  @JsonProperty("private_key")
  private String privateKey;

  public CertificateAuthorityBody(String certificate, String privateKey) {
    this.setCertificate(certificate);
    this.setPrivateKey(privateKey);
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
