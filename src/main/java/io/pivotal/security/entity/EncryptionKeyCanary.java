package io.pivotal.security.entity;

import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.UUID;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "EncryptionKeyCanary")
public class EncryptionKeyCanary implements EncryptedValueContainer {
  // Use VARBINARY to make all 3 DB types happy.
  // H2 doesn't distinguish between "binary" and "varbinary" - see
  // https://hibernate.atlassian.net/browse/HHH-9835 and
  // https://github.com/h2database/h2database/issues/345
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(length = ENCRYPTED_BYTES + NONCE_SIZE, name = "encrypted_value")
  private byte[] encryptedValue;

  @Column(length = NONCE_SIZE)
  private byte[] nonce;

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  @Override
  public byte[] getEncryptedValue() {
    return encryptedValue;
  }

  @Override
  public void setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue;
  }

  @Override
  public byte[] getNonce() {
    return nonce;
  }

  @Override
  public void setNonce(byte[] nonce) {
    this.nonce = nonce;
  }

  @Override
  public UUID getEncryptionKeyUuid() {
    return uuid;
  }

  @Override
  public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    setUuid(encryptionKeyUuid);
  }
}
