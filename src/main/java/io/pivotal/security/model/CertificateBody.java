package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateBody {
  public String ca;

  @JsonProperty("public")
  public String pub;
  @JsonProperty("private")
  public String priv;

  public CertificateBody(String ca, String pub, String priv) {
    this.ca = ca;
    this.pub = pub;
    this.priv = priv;
  }
}
