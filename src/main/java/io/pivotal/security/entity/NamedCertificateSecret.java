package io.pivotal.security.entity;

import io.pivotal.security.view.CertificateSecret;

import javax.persistence.*;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> implements SecretEncryptor {

  @Column(length = 7000)
  private String root;

  @Column(length = 7000)
  private String certificate;

  @Transient
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
    return new SecretEncryptionHelper<NamedCertificateSecret>().decryptPrivateKey(this);
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    return new SecretEncryptionHelper<NamedCertificateSecret>().encryptPrivateKey(this, privateKey);
  }

  public void setCachedItem(String privateKey) {
    this.privateKey = privateKey;
  }

  @Override
  public CertificateSecret generateView() {
    return new CertificateSecret(root, certificate, getPrivateKey()).setUpdatedAt(getUpdatedAt());
  }

  public String getCachedItem() {
    return privateKey;
  }
}