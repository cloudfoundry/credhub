package io.pivotal.security.entity;

import io.pivotal.security.view.CertificateSecret;

import javax.persistence.*;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> {

  @Column(length = 7000)
  private String root;

  @Column(length = 7000)
  private String certificate;

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
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    new SecretEncryptionHelper().refreshEncryptedValue(this, privateKey);
    return this;
  }

  @Override
  public CertificateSecret generateView() {
    return new CertificateSecret(root, certificate, getPrivateKey()).setUpdatedAt(getUpdatedAt());
  }

  @Override
  public CertificateSecret getViewInstance() {
    return new CertificateSecret();
  }
}