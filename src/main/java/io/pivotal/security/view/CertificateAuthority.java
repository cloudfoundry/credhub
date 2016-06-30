package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;

public class CertificateAuthority extends Authority<NamedCertificateAuthority, CertificateAuthority> {

  @JsonProperty("type")
  private String type;

  @JsonProperty("root")
  private CertificateAuthorityBody certificateAuthorityBody;

  public CertificateAuthority(String type, String pub, String priv) {
    setType(type);
    setCertificateBody(new CertificateAuthorityBody(pub, priv));
  }

  public CertificateAuthority() {}

  @Override
  public void populateEntity(NamedCertificateAuthority entity) {
    entity.setType(getType())
        .setPub(getCertificateAuthorityBody().getPub())
        .setPriv(getCertificateAuthorityBody().getPriv());
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