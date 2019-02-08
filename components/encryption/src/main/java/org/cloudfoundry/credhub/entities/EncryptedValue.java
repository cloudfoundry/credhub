package org.cloudfoundry.credhub.entities;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.cloudfoundry.credhub.constants.EncryptionConstants;
import org.cloudfoundry.credhub.constants.UuidConstants;
import org.cloudfoundry.credhub.util.InstantMillisecondsConverter;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(name = EncryptedValue.TABLE_NAME)
@EntityListeners(AuditingEntityListener.class)
@SuppressWarnings("PMD.AvoidFieldNameMatchingTypeName")
public class EncryptedValue {
  public static final String TABLE_NAME = "encrypted_value";

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

  @Column(length = EncryptionConstants.ENCRYPTED_BYTES + EncryptionConstants.NONCE_SIZE, name = "encrypted_value", nullable = false)
  private byte[] encryptedValue;

  @Column(length = EncryptionConstants.NONCE_SIZE, nullable = false)
  private byte[] nonce;

  public EncryptedValue() {
    super();
  }

  public EncryptedValue(final UUID encryptionKeyUuid, final String encryptedValueString, final String nonceString) {
    this(encryptionKeyUuid, encryptedValueString.getBytes(StringUtil.UTF_8), nonceString.getBytes(StringUtil.UTF_8));
  }

  public EncryptedValue(final UUID encryptionKeyUuid, final byte[] encryptedValue, final byte[] nonce) {
    super();
    this.encryptionKeyUuid = encryptionKeyUuid;
    this.nonce = nonce == null ? null : nonce.clone();
    this.encryptedValue = encryptedValue == null ? null : encryptedValue.clone();
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(final UUID uuid) {
    this.uuid = uuid;
  }

  public UUID getEncryptionKeyUuid() {
    return encryptionKeyUuid;
  }

  public void setEncryptionKeyUuid(final UUID encryptionKeyUuid) {
    this.encryptionKeyUuid = encryptionKeyUuid;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue == null ? null : encryptedValue.clone();
  }

  public void setEncryptedValue(final byte[] encryptedValue) {
    this.encryptedValue = encryptedValue == null ? null : encryptedValue.clone();
  }

  public byte[] getNonce() {
    return nonce == null ? null : nonce.clone();
  }

  public void setNonce(final byte[] nonce) {
    this.nonce = nonce == null ? null : nonce.clone();
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final EncryptedValue that = (EncryptedValue) o;

    return new EqualsBuilder()
      .append(uuid, that.uuid)
      .append(updatedAt, that.updatedAt)
      .append(encryptionKeyUuid, that.encryptionKeyUuid)
      .append(encryptedValue, that.encryptedValue)
      .append(nonce, that.nonce)
      .isEquals();
  }

  @Override
  public int hashCode() {
    int result = encryptionKeyUuid != null ? encryptionKeyUuid.hashCode() : 0;
    result = 31 * result + Arrays.hashCode(encryptedValue);
    result = 31 * result + Arrays.hashCode(nonce);
    return result;
  }
}
