package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;

public class CertificateAuthority extends BaseView<NamedCertificateAuthority, CertificateAuthority> {

  @JsonProperty("type")
  private String type;

  @JsonProperty("value")
  private CertificateAuthorityBody certificateAuthorityBody;

  public CertificateAuthority(String type, String certificate, String privateKey) {
    setType(type);
    setCertificateBody(new CertificateAuthorityBody(certificate, privateKey));
  }

  public CertificateAuthority() {
  }

  public void populateEntity(NamedCertificateAuthority entity) {
    entity.setType(getType())
        .setCertificate(getCertificateAuthorityBody().getCertificate())
        .setPrivateKey(getCertificateAuthorityBody().getPrivateKey());
  }

  @Override
  public CertificateAuthority generateView(NamedCertificateAuthority entity) {
    return this
        .setType(entity.getType())
        .setCertificateBody(new CertificateAuthorityBody(entity.getCertificate(), entity.getPrivateKey()))
        .setUpdatedAt(entity.getUpdatedAt());
  }

  public CertificateAuthorityBody getCertificateAuthorityBody() {
    return certificateAuthorityBody;
  }

  public CertificateAuthority setCertificateBody(CertificateAuthorityBody certificateAuthorityBody) {
    this.certificateAuthorityBody = certificateAuthorityBody;
    return this;
  }

  public CertificateAuthority setType(String type) {
    this.type = type;
    return this;
  }

  public String getType() {
    return type;
  }
}