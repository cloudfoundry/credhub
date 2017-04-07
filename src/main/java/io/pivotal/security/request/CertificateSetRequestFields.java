package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.pivotal.security.util.EmptyStringToNull;
import io.pivotal.security.validator.RequireAnyOf;

@SuppressWarnings("unused")
@RequireAnyOf(message = "error.missing_certificate_credentials", fields = {"ca", "certificate",
    "privateKey"})
public class CertificateSetRequestFields {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String ca;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String certificate;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;

  //only relevant for generate & regenerate that utilize the Set path
  @JsonIgnore
  private String caName;

  public CertificateSetRequestFields() {
  }

  public CertificateSetRequestFields(String privateKey, String certificate, String ca, String caName) {
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.ca = ca;
    this.caName = caName;
  }

  public CertificateSetRequestFields(String privateKey, String certificate, String ca) {
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.ca = ca;
    this.caName = null;
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

  public String getCaName() {
    return caName;
  }

  public void setCaName(String caName) {
    this.caName = caName;
  }
}
