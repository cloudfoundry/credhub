package io.pivotal.security.request;

import io.pivotal.security.validator.RequireAnyOf;

@SuppressWarnings("unused")
@RequireAnyOf(message = "error.missing_certificate_credentials", fields = { "ca", "certificate", "privateKey" })
public class CertificateSetRequestFields {
  private String ca;

  private String certificate;

  private String privateKey;

  public CertificateSetRequestFields() {}

  public CertificateSetRequestFields(String privateKey, String certificate, String ca) {
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.ca = ca;
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
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
