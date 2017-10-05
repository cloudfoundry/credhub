package io.pivotal.security.entity;

import io.pivotal.security.util.InstantMillisecondsConverter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = EncryptedValue.TABLE_NAME)
@EntityListeners(AuditingEntityListener.class)
public class EncryptedValue {
  static final String TABLE_NAME = "encrypted_value";

  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  @LastModifiedDate
  @SuppressWarnings("unused")
  //secrets are updated in place when encryption keys are rotated
  private Instant updatedAt;

  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  private UUID encryptionKeyUuid;

  @Column(length = ENCRYPTED_BYTES + NONCE_SIZE, name = "encrypted_value", nullable = false)
  private byte[] encryptedValue;

  @Column(length = NONCE_SIZE, nullable = false)
  private byte[] nonce;

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public UUID getEncryptionKeyUuid() {
    return encryptionKeyUuid;
  }

  public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    this.encryptionKeyUuid = encryptionKeyUuid;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue == null ? null : encryptedValue.clone();
  }

  public void setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue == null ? null : encryptedValue.clone();
  }

  public byte[] getNonce() {
    return nonce == null ? null : nonce.clone();
  }

  public void setNonce(byte[] nonce) {
    this.nonce = nonce == null ? null : nonce.clone();
  }
}
