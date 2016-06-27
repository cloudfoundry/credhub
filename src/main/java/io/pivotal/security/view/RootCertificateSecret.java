package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedRootCertificateSecret;

public class RootCertificateSecret extends Secret<NamedRootCertificateSecret, RootCertificateSecret> {

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
  public void populateEntity(NamedRootCertificateSecret entity) {
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
