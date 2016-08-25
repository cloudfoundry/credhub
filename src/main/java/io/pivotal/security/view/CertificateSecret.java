package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;

public class CertificateSecret extends Secret<NamedCertificateSecret, CertificateSecret> {

  @JsonProperty("value")
  private CertificateBody certificateBody;

  public CertificateSecret() {}

  public CertificateSecret(String root, String certificate, String privateKey) {
    setCertificateBody(new CertificateBody(root, certificate, privateKey));
  }

  public CertificateSecret(String root, String privateKey) {
    setCertificateBody(new CertificateBody(null, root, privateKey));
  }

  @Override
  public String getType() {
    return "certificate";
  }

  @Override
  public CertificateSecret generateView(NamedCertificateSecret entity) {
    return super
        .generateView(entity)
        .setCertificateBody(
            new CertificateBody(entity.getRoot(), entity.getCertificate(), entity.getPrivateKey()));
  }

  @Override
  public void populateEntity(NamedCertificateSecret entity) {
    entity.setRoot(getCertificateBody().getRoot())
        .setCertificate(getCertificateBody().getCertificate())
        .setPrivateKey(getCertificateBody().getPrivateKey());
  }

  public CertificateBody getCertificateBody() {
    return certificateBody;
  }

  public CertificateSecret setCertificateBody(CertificateBody certificateBody) {
    this.certificateBody = certificateBody;
    return this;
  }
}
