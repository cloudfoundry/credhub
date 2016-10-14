package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

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

  @Column
  private String caName;

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
    return SecretEncryptionHelperProvider.getInstance().retrieveClearTextValue(this);
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedValue(this, privateKey);
    return this;
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.CERTIFICATE;
  }

  public NamedCertificateSecret setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public String getCaName() {
    return caName;
  }
}
