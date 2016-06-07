package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret {

  @Column(nullable = true)
  public String ca;

  @Column(nullable = true)
  public String pub;

  @Column(nullable = true)
  public String priv;

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name, String ca, String pub, String priv) {
    super(name);

    this.ca = ca;
    this.pub = pub;
    this.priv = priv;
  }
}