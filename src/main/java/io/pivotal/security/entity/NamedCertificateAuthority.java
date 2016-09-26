package io.pivotal.security.entity;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.Instant;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_BYTES;

@Entity
@Table(name = "NamedCertificateAuthority")
@EntityListeners(AuditingEntityListener.class)
public class NamedCertificateAuthority implements EncryptedValueContainer {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column()
  private String type;

  @Column(length = 7000)
  private String certificate;

  @Column(length = ENCRYPTED_BYTES + NONCE_BYTES, name = "encrypted_value")
  private byte[] encryptedValue;

  @Column(length = NONCE_BYTES)
  private byte[] nonce;

  @Convert(converter = InstantSecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  @LastModifiedDate
  private Instant updatedAt;

  @SuppressWarnings("unused")
  public NamedCertificateAuthority() {
  }

  public NamedCertificateAuthority(String name) {
    this.name = name;
  }

  @SuppressWarnings("unused")
  public long getId() {
    return id;
  }

  @SuppressWarnings("unused")
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

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public NamedCertificateAuthority setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
    return this;
  }

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateAuthority setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getPrivateKey() {
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public NamedCertificateAuthority setPrivateKey(String privateKey) {
    new SecretEncryptionHelper().refreshEncryptedValue(this, privateKey);
    return this;
  }

  public String getType() {
    return type;
  }

  public NamedCertificateAuthority setType(String type) {
    this.type = type;
    return this;
  }

  public byte[] getNonce() {
    return nonce;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue;
  }

  public void setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue;
  }

  public void setNonce(byte[] nonce) {
    this.nonce = nonce;
  }
}