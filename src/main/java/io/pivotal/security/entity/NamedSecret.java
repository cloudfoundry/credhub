package io.pivotal.security.entity;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.Instant;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_BYTES;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecret implements EncryptedValueContainer {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(length = ENCRYPTED_BYTES + NONCE_BYTES, name = "encrypted_value")
  private byte[] encryptedValue;

  @Column(length = NONCE_BYTES)
  private byte[] nonce;

  @Convert(converter = InstantSecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  @LastModifiedDate
  private Instant updatedAt;

  @Column
  private String uuid;

  public NamedSecret() {
    this(null);
  }

  public NamedSecret(String name) {
    this.name = name;
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue;
  }

  public void setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue;
  }

  public byte[] getNonce() {
    return nonce;
  }

  public void setNonce(byte[] nonce) {
    this.nonce = nonce;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public NamedSecret setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
    return this;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  @PrePersist
  @PreUpdate
  public void updateUuidOnPersist() {
    this.uuid = UuidGeneratorProvider.getInstance().makeUuid();
  }
}