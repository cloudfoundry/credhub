package org.cloudfoundry.credhub.entities;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.cloudfoundry.credhub.constants.EncryptionConstants;
import org.hibernate.annotations.GenericGenerator;

import static org.cloudfoundry.credhub.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "encryption_key_canary")
public class EncryptionKeyCanary {

  // Use VARBINARY to make all 3 DB types happy.
  // H2 doesn't distinguish between "binary" and "varbinary" - see
  // https://hibernate.atlassian.net/browse/HHH-9835 and
  // https://github.com/h2database/h2database/issues/345
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "org.cloudfoundry.credhub.entities.UuidGenerator")
  private UUID uuid;

  @Column(length = EncryptionConstants.ENCRYPTED_BYTES + EncryptionConstants.NONCE_SIZE, name = "encrypted_value")
  private byte[] encryptedCanaryValue;

  @Column(length = EncryptionConstants.NONCE_SIZE)
  private byte[] nonce;

  @Column(length = EncryptionConstants.SALT_SIZE)
  private byte[] salt;

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(final UUID uuid) {
    this.uuid = uuid;
  }

  public byte[] getEncryptedCanaryValue() {
    return encryptedCanaryValue == null ? null : encryptedCanaryValue.clone();
  }

  public void setEncryptedCanaryValue(final byte[] encryptedCanaryValue) {
    this.encryptedCanaryValue = encryptedCanaryValue == null ? null : encryptedCanaryValue.clone();
  }

  public byte[] getNonce() {
    return nonce == null ? null : nonce.clone();
  }

  public void setNonce(final byte[] nonce) {
    this.nonce = nonce == null ? null : nonce.clone();
  }

  public void setEncryptionKeyUuid(final UUID encryptionKeyUuid) {
    setUuid(encryptionKeyUuid);
  }

  public byte[] getSalt() {
    return salt == null ? null : salt.clone();
  }

  public void setSalt(final byte[] salt) {
    this.salt = salt == null ? null : salt.clone();
  }
}
