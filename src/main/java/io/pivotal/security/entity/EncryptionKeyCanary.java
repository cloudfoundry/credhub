package io.pivotal.security.entity;

import org.hibernate.annotations.GenericGenerator;

import java.util.List;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.EncryptionConstants.SALT_SIZE;
import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;
import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.apache.commons.lang3.ArrayUtils.toObject;

@Entity
@Table(name = "EncryptionKeyCanary")
public class EncryptionKeyCanary {

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
  private byte[] encryptedCanaryValue;

  @Column(length = NONCE_SIZE)
  private byte[] nonce;

  @Column(length = SALT_SIZE)
  private byte[] salt;

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public byte[] getEncryptedCanaryValue() {
    return encryptedCanaryValue  == null ? null : encryptedCanaryValue.clone();
  }

  public EncryptionKeyCanary setEncryptedCanaryValue(byte[] encryptedCanaryValue) {
    this.encryptedCanaryValue = encryptedCanaryValue == null ? null : encryptedCanaryValue.clone();
    return this;
  }

  public byte[] getNonce() {
    return nonce == null ? null : nonce.clone();
  }

  public EncryptionKeyCanary setNonce(byte[] nonce) {
    this.nonce = nonce == null ? null : nonce.clone();
    return this;
  }


  public EncryptionKeyCanary setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    setUuid(encryptionKeyUuid);
    return this;
  }

  public List<Byte> getSalt() {
    return salt == null ? null : unmodifiableList(asList(toObject(salt)));
  }

  public void setSalt(byte[] salt) {
    this.salt = salt == null ? null : salt.clone();
  }
}
