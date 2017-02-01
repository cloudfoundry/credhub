package io.pivotal.security.secret;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Certificate implements Secret {
  private final String caCertificate;
  private final String publicKeyCertificate;
  private final String privateKey;

  public Certificate(String caCertificate, String publicKeyCertificate, String privateKey) {
    this.caCertificate = caCertificate;
    this.publicKeyCertificate = publicKeyCertificate;
    this.privateKey = privateKey;
  }

  @JsonProperty("ca")
  public String getCaCertificate() {
    return caCertificate;
  }

  @JsonProperty("certificate")
  public String getPublicKeyCertificate() {
    return publicKeyCertificate;
  }

  @JsonProperty("private_key")
  public String getPrivateKey() {
    return privateKey;
  }
}
