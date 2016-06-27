package io.pivotal.security.entity;

import io.pivotal.security.view.RootCertificateSecret;
import io.pivotal.security.view.Secret;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedRootCertificateSecret extends NamedSecret<NamedRootCertificateSecret> {

  @Column(nullable = true, length = 7000)
  private String pub;

  @Column(nullable = true, length = 7000)
  private String priv;

  public static NamedRootCertificateSecret make(String name, String pub, String priv) {
    return new NamedRootCertificateSecret(name)
        .setPub(pub)
        .setPriv(priv);
  }

  public NamedRootCertificateSecret() {
  }

  public NamedRootCertificateSecret(String name) {
    super(name);
  }


  public String getPub() {
    return pub;
  }

  public NamedRootCertificateSecret setPub(String pub) {
    this.pub = pub;
    return this;
  }

  public String getPriv() {
    return priv;
  }

  public NamedRootCertificateSecret setPriv(String priv) {
    this.priv = priv;
    return this;
  }

  @Override
  public Secret generateView() {
    return new RootCertificateSecret(pub, priv);
  }
}