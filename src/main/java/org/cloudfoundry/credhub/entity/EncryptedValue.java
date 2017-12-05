package org.cloudfoundry.credhub.entity;

import org.cloudfoundry.credhub.util.InstantMillisecondsConverter;
import org.cloudfoundry.credhub.constants.UuidConstants;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static org.cloudfoundry.credhub.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static org.cloudfoundry.credhub.constants.EncryptionConstants.NONCE_SIZE;

@Entity
@Table(name = EncryptedValue.TABLE_NAME)
@EntityListeners(AuditingEntityListener.class)
public class EncryptedValue {
  static final String TABLE_NAME = "encrypted_value";

  @Id
  @Column(length = UuidConstants.UUID_BYTES, columnDefinition = "VARBINARY")
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

  @Column(length = UuidConstants.UUID_BYTES, columnDefinition = "VARBINARY")
  private UUID encryptionKeyUuid;

  @Column(length = ENCRYPTED_BYTES + NONCE_SIZE, name = "encrypted_value", nullable = false)
  private byte[] encryptedValue;

  @Column(length = NONCE_SIZE, nullable = false)
  private byte[] nonce;

  public EncryptedValue() {
  }

  public EncryptedValue(UUID encryptionKeyUuid, String encryptedValueString, String nonceString) {
    this(encryptionKeyUuid, encryptedValueString.getBytes(), nonceString.getBytes());
  }

  public EncryptedValue(UUID encryptionKeyUuid, byte[] encryptedValue, byte[] nonce) {
    this.encryptionKeyUuid = encryptionKeyUuid;
    this.nonce = nonce == null ? null : nonce.clone();
    this.encryptedValue = encryptedValue == null ? null : encryptedValue.clone();
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public UUID getEncryptionKeyUuid() {
    return encryptionKeyUuid;
  }

  public EncryptedValue setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    this.encryptionKeyUuid = encryptionKeyUuid;
    return this;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue == null ? null : encryptedValue.clone();
  }

  public EncryptedValue setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue == null ? null : encryptedValue.clone();
    return this;
  }

  public byte[] getNonce() {
    return nonce == null ? null : nonce.clone();
  }

  public EncryptedValue setNonce(byte[] nonce) {
    this.nonce = nonce == null ? null : nonce.clone();
    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    EncryptedValue that = (EncryptedValue) o;

    if (encryptionKeyUuid != null ? !encryptionKeyUuid.equals(that.encryptionKeyUuid) : that.encryptionKeyUuid != null)
      return false;
    if (!Arrays.equals(encryptedValue, that.encryptedValue)) return false;
    return Arrays.equals(nonce, that.nonce);
  }

  @Override
  public int hashCode() {
    int result = encryptionKeyUuid != null ? encryptionKeyUuid.hashCode() : 0;
    result = 31 * result + Arrays.hashCode(encryptedValue);
    result = 31 * result + Arrays.hashCode(nonce);
    return result;
  }
}
