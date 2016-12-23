package io.pivotal.security.entity;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "NamedCanary")
public class EncryptionKeyCanary implements EncryptedValueContainer {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(length = ENCRYPTED_BYTES + NONCE, name = "encrypted_value")
  private byte[] encryptedValue;

  @Column(length = NONCE)
  private byte[] nonce;

  public EncryptionKeyCanary() {
    this(null);
  }

  public EncryptionKeyCanary(String name) {
    this.name = name;
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
}
