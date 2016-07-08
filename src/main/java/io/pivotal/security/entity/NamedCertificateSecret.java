package io.pivotal.security.entity;

import io.pivotal.security.view.CertificateSecret;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> {

  @Column(nullable = true, length = 7000)
  private String ca;

  @Column(nullable = true, length = 7000)
  private String certificate;

  @Column(nullable = true, length = 7000)
  private String privateKey;

  public static NamedCertificateSecret make(String name, String ca, String certificate, String privateKey) {
    return new NamedCertificateSecret(name)
        .setCa(ca)
        .setCertificate(certificate)
        .setPrivateKey(privateKey);
  }

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

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateSecret setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
    return this;
  }

  @Override
  public CertificateSecret generateView() {
    return new CertificateSecret(ca, certificate, privateKey).setUpdatedAt(getUpdatedAt());
  }
}