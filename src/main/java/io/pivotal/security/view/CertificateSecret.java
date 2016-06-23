package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;

public class CertificateSecret extends Secret<NamedCertificateSecret, CertificateSecret> {

  @JsonProperty("certificate")
  private CertificateBody certificateBody;

  public CertificateSecret(String ca, String pub, String priv) {
    setCertificateBody(new CertificateBody(ca, pub, priv));
  }

  public CertificateSecret(String ca, String priv) {
    setCertificateBody(new CertificateBody(null, ca, priv));
  }

  @Override
  public String getType() {
    return "certificate";
  }

  @Override
  public void populateEntity(NamedCertificateSecret entity) {
    entity.setCa(getCertificateBody().getCa())
        .setPub(getCertificateBody().getPub())
        .setPriv(getCertificateBody().getPriv());
  }

  public CertificateBody getCertificateBody() {
    return certificateBody;
  }

  public void setCertificateBody(CertificateBody certificateBody) {
    this.certificateBody = certificateBody;
  }
}
