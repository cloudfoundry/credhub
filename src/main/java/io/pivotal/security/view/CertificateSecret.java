package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;

public class CertificateSecret extends Secret<NamedCertificateSecret, CertificateSecret> {

  @JsonProperty("certificate")
  private CertificateBody certificateBody;

  public CertificateSecret(String ca, String certificate, String privateKey) {
    setCertificateBody(new CertificateBody(ca, certificate, privateKey));
  }

  public CertificateSecret(String ca, String privateKey) {
    setCertificateBody(new CertificateBody(null, ca, privateKey));
  }

  @Override
  public String getType() {
    return "certificate";
  }

  @Override
  public void populateEntity(NamedCertificateSecret entity) {
    entity.setCa(getCertificateBody().getCa())
        .setCertificate(getCertificateBody().getCertificate())
        .setPrivateKey(getCertificateBody().getPrivateKey());
  }

  public CertificateBody getCertificateBody() {
    return certificateBody;
  }

  public void setCertificateBody(CertificateBody certificateBody) {
    this.certificateBody = certificateBody;
  }
}
