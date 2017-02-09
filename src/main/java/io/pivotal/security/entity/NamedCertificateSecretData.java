package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecretData extends NamedSecretData<NamedCertificateSecretData> {
  public static final String SECRET_TYPE = "certificate";

  @Column(length = 7000)
  private String ca;

  @Column(length = 7000)
  private String certificate;

  @Column
  private String caName;

  public NamedCertificateSecretData() {
  }

  public NamedCertificateSecretData(String name) {
    super(name);
  }

  public String getCa() {
    return ca;
  }

  public NamedCertificateSecretData setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateSecretData setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getPrivateKey() {
    return SecretEncryptionHelperProvider.getInstance().retrieveClearTextValue(this);
  }

  public NamedCertificateSecretData setPrivateKey(String privateKey) {
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedValue(this, privateKey);
    return this;
  }

  public NamedCertificateSecretData setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.CERTIFICATE;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  @Override
  void copyIntoImpl(NamedCertificateSecretData copy) {
    copy.setCaName(caName);
    copy.setCa(ca);
    copy.setCertificate(certificate);
  }
}
