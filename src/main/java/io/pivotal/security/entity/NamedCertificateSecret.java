package io.pivotal.security.entity;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret {

  @Column(length = 7000)
  private String ca;

  @Column(length = 7000)
  private String certificate;

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name) {
    super(name);
  }

  public NamedCertificateSecret(String name, String ca, String certificate, String privateKey) {
    super(name);
    this.ca = ca;
    this.certificate = certificate;
    setPrivateKey(privateKey);
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
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    new SecretEncryptionHelper().refreshEncryptedValue(this, privateKey);
    return this;
  }
}