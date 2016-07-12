package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;

public class CertificateAuthority extends Authority<NamedCertificateAuthority, CertificateAuthority> {

  @JsonProperty("type")
  private String type;

  @JsonProperty("ca")
  private CertificateAuthorityBody certificateAuthorityBody;

  public CertificateAuthority(String type, String certificate, String privateKey) {
    setType(type);
    setCertificateBody(new CertificateAuthorityBody(certificate, privateKey));
  }

  public CertificateAuthority() {
  }

  @Override
  public void populateEntity(NamedCertificateAuthority entity) {
    entity.setType(getType())
        .setCertificate(getCertificateAuthorityBody().getCertificate())
        .setPrivateKey(getCertificateAuthorityBody().getPrivateKey());
  }

  public CertificateAuthorityBody getCertificateAuthorityBody() {
    return certificateAuthorityBody;
  }

  public void setCertificateBody(CertificateAuthorityBody certificateAuthorityBody) {
    this.certificateAuthorityBody = certificateAuthorityBody;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getType() {
    return type;
  }
}