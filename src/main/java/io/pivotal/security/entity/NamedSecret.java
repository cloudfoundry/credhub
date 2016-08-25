package io.pivotal.security.entity;

import io.pivotal.security.util.UuidGenerator;
import io.pivotal.security.view.Secret;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecret<T> implements EncryptedValueContainer {
  public static final int NONCE_BYTES = 16;
  static final int ENCRYPTED_BYTES = 7000;
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(length = ENCRYPTED_BYTES+NONCE_BYTES, name = "encrypted_value")
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

  @Transient
  UuidGenerator uuidGenerator;

  public NamedSecret() {
    uuidGenerator = new UuidGenerator();
  }

  public NamedSecret(String name) {
    this();
    this.setName(name);
  }

  public long getId() {
    return id;
  }

  public T setId(long id) {
    this.id = id;
    return (T) this;
  }

  public String getName() {
    return name;
  }

  public T setName(String name) {
    this.name = name;
    return (T) this;
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

  public abstract Secret getViewInstance();

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public T setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
    return (T) this;
  }

  public String getUuid() {
    return uuid;
  }

  public UuidGenerator getUuidGenerator() {
    return uuidGenerator;
  }

  public T setUuidGenerator(UuidGenerator uuidGenerator) {
    this.uuidGenerator = uuidGenerator;
    return (T) this;
  }

  @PrePersist
  @PreUpdate
  public void updateUuidOnPersist() {
    this.uuid = uuidGenerator.makeUuid();
  }
}
