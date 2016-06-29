package io.pivotal.security.entity;

import io.pivotal.security.view.CertificateAuthority;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateAuthority")
@DiscriminatorValue("ca")
public class NamedCertificateAuthority extends NamedAuthority<NamedCertificateAuthority> {
  @Column(nullable = true, length = 7000)
  private String pub;

  @Column(nullable = true, length = 7000)
  private String priv;

  public static NamedCertificateAuthority make(String name, String ca, String pub, String priv) {
    return new NamedCertificateAuthority(name)
        .setPub(pub)
        .setPriv(priv);
  }

  @SuppressWarnings("unused")
  public NamedCertificateAuthority() {
  }

  public NamedCertificateAuthority(String name) {
    super(name);
  }

  public String getPub() {
    return pub;
  }

  public NamedCertificateAuthority setPub(String pub) {
    this.pub = pub;
    return this;
  }

  public String getPriv() {
    return priv;
  }

  public NamedCertificateAuthority setPriv(String priv) {
    this.priv = priv;
    return this;
  }

  @Override
  public CertificateAuthority generateView() {
    return new CertificateAuthority(pub, priv).setUpdatedAt(getUpdatedAt());
  }
}