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
  private String type;

  @Column(nullable = true, length = 7000)
  private String pub;

  @Column(nullable = true, length = 7000)
  private String priv;

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

  public String getType() {
    return type;
  }

  public NamedCertificateAuthority setType(String type){
    this.type = type;
    return this;
  }

  @Override
  public CertificateAuthority generateView() {
    return new CertificateAuthority(type, pub, priv).setUpdatedAt(getUpdatedAt());
  }
}