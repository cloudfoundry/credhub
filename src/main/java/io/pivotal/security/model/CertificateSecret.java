package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;

import javax.validation.constraints.NotNull;

public class CertificateSecret implements Secret<NamedCertificateSecret> {

  @NotNull
  private final String type = "certificate";

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
    return type;
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return new NamedCertificateSecret(name);
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
