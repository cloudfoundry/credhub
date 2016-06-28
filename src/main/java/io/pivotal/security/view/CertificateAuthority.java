package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;

public class CertificateAuthority extends Authority<NamedCertificateAuthority, CertificateAuthority> {
  @JsonProperty("root")
  private CertificateAuthorityBody certificateAuthorityBody;

  public CertificateAuthority(String pub, String priv) {
    setCertificateBody(new CertificateAuthorityBody(pub, priv));
  }

  public CertificateAuthority() {}

  @Override
  public void populateEntity(NamedCertificateAuthority entity) {
    entity.setPub(getCertificateAuthorityBody().getPub())
        .setPriv(getCertificateAuthorityBody().getPriv());
  }

  public CertificateAuthorityBody getCertificateAuthorityBody() {
    return certificateAuthorityBody;
  }

  public void setCertificateBody(CertificateAuthorityBody certificateAuthorityBody) {
    this.certificateAuthorityBody = certificateAuthorityBody;
  }
}