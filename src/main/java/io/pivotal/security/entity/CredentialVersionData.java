package io.pivotal.security.entity;

import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.InstantMillisecondsConverter;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;
import javax.persistence.CascadeType;
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
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "credential_version")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
public abstract class CredentialVersionData<Z extends CredentialVersionData> {

  // Use VARBINARY to make all 3 DB types happy.
  // H2 doesn't distinguish between "binary" and "varbinary" - see
  // https://hibernate.atlassian.net/browse/HHH-9835 and
  // https://github.com/h2database/h2database/issues/345
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @OneToOne(cascade = CascadeType.ALL)
  @NotFound(action = NotFoundAction.IGNORE)
  @JoinColumn(name = "encrypted_value_uuid")
  private EncryptedValue encryptedCredentialValue;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  private Instant versionCreatedAt;

  @ManyToOne
  @JoinColumn(name = "credential_uuid", nullable = false)
  private Credential credential;

  public CredentialVersionData(Credential name) {
    if (this.credential != null) {
      this.credential.setName(name.getName());
    } else {
      setCredential(name);
    }
  }

  public CredentialVersionData(String name) {
    this(new Credential(name));
  }

  public CredentialVersionData() {
    this((String) null);
  }

  public UUID getUuid() {
    return uuid;
  }

  public Z setUuid(UUID uuid) {
    this.uuid = uuid;
    return (Z) this;
  }

  public Credential getCredential() {
    return credential;
  }

  public void setCredential(Credential credential) {
    this.credential = credential;
  }

  public byte[] getEncryptedValue() {
    return encryptedCredentialValue !=null ? encryptedCredentialValue.getEncryptedValue() : null;
  }

  public Z setValuesFromEncryption(Encryption encryptedValue){
    if (this.encryptedCredentialValue == null) {
      this.encryptedCredentialValue = new EncryptedValue();
    }
    encryptedCredentialValue.setNonce(encryptedValue.nonce);
    encryptedCredentialValue.setEncryptionKeyUuid(encryptedValue.canaryUuid);
    encryptedCredentialValue.setEncryptedValue(encryptedValue.encryptedValue);
    return (Z) this;
  }

  public Z setEncryptedValue(byte[] encryptedValue) {
    if (this.encryptedCredentialValue == null) {
      this.encryptedCredentialValue = new EncryptedValue();
    }
    this.encryptedCredentialValue.setEncryptedValue(encryptedValue);
    return (Z) this;
  }

  public byte[] getNonce() {
    return encryptedCredentialValue !=null ? this.encryptedCredentialValue.getNonce() : null;
  }

  public Z setNonce(byte[] nonce) {
    if (this.encryptedCredentialValue == null) {
      this.encryptedCredentialValue = new EncryptedValue();
    }
    this.encryptedCredentialValue.setNonce(nonce);
    return (Z) this;
  }

  public abstract String getCredentialType();

  public UUID getEncryptionKeyUuid() {
    return encryptedCredentialValue != null ? encryptedCredentialValue.getEncryptionKeyUuid() : null;
  }

  public Z setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    if (this.encryptedCredentialValue == null) {
      this.encryptedCredentialValue = new EncryptedValue();
    }
    this.encryptedCredentialValue.setEncryptionKeyUuid(encryptionKeyUuid);
    return (Z) this;
  }

  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    this.versionCreatedAt = versionCreatedAt;
    return (Z) this;
  }
}
