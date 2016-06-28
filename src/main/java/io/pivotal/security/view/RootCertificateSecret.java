package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;

public class RootCertificateSecret extends Secret<NamedCertificateSecret, RootCertificateSecret> {

  @JsonProperty("root")
  private RootCertificateBody rootCertificateBody;

  public RootCertificateSecret(String pub, String priv) {
    setCertificateBody(new RootCertificateBody(pub, priv));
  }

  public RootCertificateSecret() {}

  @Override
  public String getType() {
    return null;
  }

  @Override
  public void populateEntity(NamedCertificateSecret entity) {
    entity.setPub(getRootCertificateBody().getPub())
        .setPriv(getRootCertificateBody().getPriv());
  }

  public RootCertificateBody getRootCertificateBody() {
    return rootCertificateBody;
  }

  public void setCertificateBody(RootCertificateBody rootCertificateBody) {
    this.rootCertificateBody = rootCertificateBody;
  }
}
