package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateBody extends RootCertificateBody {
  private String ca;

  public CertificateBody(String ca, String pub, String priv) {
    super(pub, priv);
    this.setCa(ca);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }
}
