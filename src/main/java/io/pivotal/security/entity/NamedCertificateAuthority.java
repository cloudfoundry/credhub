package io.pivotal.security.entity;

import io.pivotal.security.view.CertificateAuthority;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "NamedCertificateAuthority")
@EntityListeners(AuditingEntityListener.class)
public class NamedCertificateAuthority {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(nullable = false)
  @CreatedDate
  @LastModifiedDate
  private LocalDateTime updatedAt;

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
    this.name = name;
  }

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateAuthority setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public long getId() {
    return id;
  }

  public NamedCertificateAuthority setId(long id) {
    this.id = id;
    return this;
  }

  public String getName() {
    return name;
  }

  public NamedCertificateAuthority setName(String name) {
    this.name = name;
    return this;
  }

  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }

  public NamedCertificateAuthority setUpdatedAt(LocalDateTime updatedAt) {
    this.updatedAt = updatedAt;
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

  public NamedCertificateAuthority setType(String type) {
    this.type = type;
    return this;
  }

  public CertificateAuthority generateView() {
    return new CertificateAuthority(type, certificate, privateKey).setUpdatedAt(getUpdatedAt());
  }
}