package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateBody {
  @JsonProperty("ca")
  private String ca;
  @JsonProperty("public")
  private String pub;
  @JsonProperty("private")
  private String priv;

  public CertificateBody(String ca, String pub, String priv) {
    this.setCa(ca);
    this.setPub(pub);
    this.setPriv(priv);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getPub() {
    return pub;
  }

  public void setPub(String pub) {
    this.pub = pub;
  }

  public String getPriv() {
    return priv;
  }

  public void setPriv(String priv) {
    this.priv = priv;
  }
}
