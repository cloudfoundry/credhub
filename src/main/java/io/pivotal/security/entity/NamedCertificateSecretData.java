package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;
import org.apache.commons.lang3.StringUtils;

@Entity
@DiscriminatorValue("cert")
@SecondaryTable(
    name = NamedCertificateSecretData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class NamedCertificateSecretData extends NamedSecretData<NamedCertificateSecretData> {

  public static final String SECRET_TYPE = "certificate";
  static final String TABLE_NAME = "CertificateSecret";

  @Column(table = NamedCertificateSecretData.TABLE_NAME, length = 7000)
  private String ca;

  @Column(table = NamedCertificateSecretData.TABLE_NAME, length = 7000)
  private String certificate;

  @Column(table = NamedCertificateSecretData.TABLE_NAME)
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

  public String getCaName() {
    return caName;
  }

  public NamedCertificateSecretData setCaName(String caName) {
    this.caName = !StringUtils.isEmpty(caName) ? StringUtils.prependIfMissing(caName, "/") : caName;
    return this;
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
