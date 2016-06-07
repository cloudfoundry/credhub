package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret {

  @Column(nullable = true)
  private String ca;

  @Column(nullable = true)
  private String pub;

  @Column(nullable = true)
  private String priv;

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name, String ca, String pub, String priv) {
    super(name);

    this.setCa(ca);
    this.setPub(pub);
    this.setPriv(priv);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getPub() {
    return pub;
  }

  public void setPub(String pub) {
    this.pub = pub;
  }

  public String getPriv() {
    return priv;
  }

  public void setPriv(String priv) {
    this.priv = priv;
  }
}