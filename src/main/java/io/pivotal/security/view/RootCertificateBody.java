package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RootCertificateBody {

  @JsonProperty("public")
  private String pub;
  @JsonProperty("private")
  private String priv;

  public RootCertificateBody(String pub, String priv) {
    this.setPub(pub);
    this.setPriv(priv);
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
