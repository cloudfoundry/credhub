package org.cloudfoundry.credhub.entity;

import org.apache.commons.lang3.StringUtils;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue("cert")
@SecondaryTable(
    name = CertificateCredentialVersionData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class CertificateCredentialVersionData extends CredentialVersionData<CertificateCredentialVersionData> {

  public static final String CREDENTIAL_TYPE = "certificate";
  static final String TABLE_NAME = "certificate_credential";

  @Column(table = CertificateCredentialVersionData.TABLE_NAME, length = 7000)
  private String ca;

  @Column(table = CertificateCredentialVersionData.TABLE_NAME, length = 7000)
  private String certificate;

  @Column(table = CertificateCredentialVersionData.TABLE_NAME)
  private String caName;

  @Column(table = CertificateCredentialVersionData.TABLE_NAME)
  private boolean transitional;

  public CertificateCredentialVersionData() {
  }

  public CertificateCredentialVersionData(String name) {
    super(name);
  }

  public String getName() {
    return super.getCredential().getName();
  }

  public String getCa() {
    return ca;
  }

  public CertificateCredentialVersionData setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getCertificate() {
    return certificate;
  }

  public CertificateCredentialVersionData setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  public CertificateCredentialVersionData setCaName(String caName) {
    this.caName = !StringUtils.isEmpty(caName) ? StringUtils.prependIfMissing(caName, "/") : caName;
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }

  public CertificateCredentialVersionData setTransitional(boolean transitional) {
    this.transitional = transitional;
    return this;
  }

  public boolean isTransitional() {
    return transitional;
  }
}
