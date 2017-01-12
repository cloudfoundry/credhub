package io.pivotal.security.secret;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Certificate implements Secret {
  private final String caCertificate;
  private final String certificate;
  private final String privateKey;

  public Certificate(String caCertificate, String certificate, String privateKey) {
    this.caCertificate = caCertificate;
    this.certificate = certificate;
    this.privateKey = privateKey;
  }

  @JsonProperty("ca")
  public String getCaCertificate() {
    return caCertificate;
  }

  @JsonProperty("certificate")
  public String getCertificate() {
    return certificate;
  }

  @JsonProperty("private_key")
  public String getPrivateKey() {
    return privateKey;
  }
}
