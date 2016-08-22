package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateBody {
  @JsonProperty("root")
  private String root;
  @JsonProperty("certificate")
  private String certificate;
  @JsonProperty("private_key")
  private String privateKey;

  public CertificateBody(String root, String certificate, String privateKey) {
    this.setRoot(root);
    this.setCertificate(certificate);
    this.setPrivateKey(privateKey);
  }

  public String getRoot() {
    return root;
  }

  public void setRoot(String root) {
    this.root = root;
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
