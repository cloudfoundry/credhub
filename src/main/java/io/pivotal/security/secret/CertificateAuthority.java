package io.pivotal.security.secret;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateAuthority implements Secret {
  private final String type;
  private final String certificate;
  private final String privateKey;

  public CertificateAuthority(String type, String certificate, String privateKey) {
    this.type = type;
    this.certificate = certificate;
    this.privateKey = privateKey;
  }

  @JsonIgnore
  public String getType() {
    return type;
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
