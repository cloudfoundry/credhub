package io.pivotal.security.entity;

import io.pivotal.security.model.CertificateSecret;

import javax.persistence.*;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> {

  @Column(nullable = true, length = 7000)
  private String ca;

  @Column(nullable = true, length = 7000)
  private String pub;

  @Column(nullable = true, length = 7000)
  private String priv;

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name) {
    super(name);
  }

  public String getCa() {
    return ca;
  }

  public NamedCertificateSecret setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getPub() {
    return pub;
  }

  public NamedCertificateSecret setPub(String pub) {
    this.pub = pub;
    return this;
  }

  public String getPriv() {
    return priv;
  }

  public NamedCertificateSecret setPriv(String priv) {
    this.priv = priv;
    return this;
  }

  @Override
  public CertificateSecret convertToModel() {
    return new CertificateSecret(ca, pub, priv);
  }
}