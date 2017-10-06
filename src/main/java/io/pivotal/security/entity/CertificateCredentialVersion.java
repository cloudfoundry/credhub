package io.pivotal.security.entity;

import org.apache.commons.lang3.StringUtils;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue("cert")
@SecondaryTable(
    name = CertificateCredentialVersion.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class CertificateCredentialVersion extends CredentialVersion<CertificateCredentialVersion> {

  public static final String CREDENTIAL_TYPE = "certificate";
  static final String TABLE_NAME = "certificate_credential";

  @Column(table = CertificateCredentialVersion.TABLE_NAME, length = 7000)
  private String ca;

  @Column(table = CertificateCredentialVersion.TABLE_NAME, length = 7000)
  private String certificate;

  @Column(table = CertificateCredentialVersion.TABLE_NAME)
  private String caName;

  public CertificateCredentialVersion() {
  }

  public CertificateCredentialVersion(String name) {
    super(name);
  }

  public String getName() {
    return super.getCredentialName().getName();
  }

  public String getCa() {
    return ca;
  }

  public CertificateCredentialVersion setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getCertificate() {
    return certificate;
  }

  public CertificateCredentialVersion setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  public CertificateCredentialVersion setCaName(String caName) {
    this.caName = !StringUtils.isEmpty(caName) ? StringUtils.prependIfMissing(caName, "/") : caName;
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
