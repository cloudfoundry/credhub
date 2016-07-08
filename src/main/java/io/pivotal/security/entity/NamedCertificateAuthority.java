package io.pivotal.security.entity;

import io.pivotal.security.view.CertificateAuthority;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateAuthority")
@DiscriminatorValue("ca")
public class NamedCertificateAuthority extends NamedAuthority<NamedCertificateAuthority> {
  @Column(nullable = true, length = 7000)
  private String type;

  @Column(nullable = true, length = 7000)
  private String certificate;

  @Column(nullable = true, length = 7000)
  private String privateKey;

  @SuppressWarnings("unused")
  public NamedCertificateAuthority() {
  }

  public NamedCertificateAuthority(String name) {
    super(name);
  }

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateAuthority setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public NamedCertificateAuthority setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
    return this;
  }

  public String getType() {
    return type;
  }

  public NamedCertificateAuthority setType(String type){
    this.type = type;
    return this;
  }

  @Override
  public CertificateAuthority generateView() {
    return new CertificateAuthority(type, certificate, privateKey).setUpdatedAt(getUpdatedAt());
  }
}