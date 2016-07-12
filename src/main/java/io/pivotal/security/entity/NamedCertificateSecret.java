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
  private String root;

  @Column(nullable = true, length = 7000)
  private String certificate;

  @Column(nullable = true, length = 7000)
  private String privateKey;

  public static NamedCertificateSecret make(String name, String root, String certificate, String privateKey) {
    return new NamedCertificateSecret(name)
        .setRoot(root)
        .setCertificate(certificate)
        .setPrivateKey(privateKey);
  }

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name) {
    super(name);
  }

  public String getRoot() {
    return root;
  }

  public NamedCertificateSecret setRoot(String root) {
    this.root = root;
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
    return new CertificateSecret(root, certificate, privateKey).setUpdatedAt(getUpdatedAt());
  }
}