package io.pivotal.security.entity;

import io.pivotal.security.view.Secret;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.Instant;

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

  public NamedSecret() {
    this(null);
  }

  public NamedSecret(String name) {
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

  public T setUuid(String uuid) {
    this.uuid = uuid;
    return (T) this;
  }

  @PrePersist
  @PreUpdate
  public void updateUuidOnPersist() {
    this.uuid = UuidGeneratorProvider.getInstance().makeUuid();
  }
}
