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
    name = CertificateCredentialData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class CertificateCredentialData extends CredentialData<CertificateCredentialData> {

  public static final String CREDENTIAL_TYPE = "certificate";
  static final String TABLE_NAME = "CertificateCredential";

  @Column(table = CertificateCredentialData.TABLE_NAME, length = 7000)
  private String ca;

  @Column(table = CertificateCredentialData.TABLE_NAME, length = 7000)
  private String certificate;

  @Column(table = CertificateCredentialData.TABLE_NAME)
  private String caName;

  public CertificateCredentialData() {
  }

  public CertificateCredentialData(String name) {
    super(name);
  }

  public String getName() {
    return super.getCredentialName().getName();
  }

  public String getCa() {
    return ca;
  }

  public CertificateCredentialData setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getCertificate() {
    return certificate;
  }

  public CertificateCredentialData setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  public CertificateCredentialData setCaName(String caName) {
    this.caName = !StringUtils.isEmpty(caName) ? StringUtils.prependIfMissing(caName, "/") : caName;
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
