package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

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
import javax.persistence.Table;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecretData<Z extends NamedSecretData> implements EncryptedValueContainer {
  static String SECRET_TYPE;
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

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  private Instant versionCreatedAt;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  @LastModifiedDate
  @SuppressWarnings("unused")
  private Instant updatedAt;

  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  private UUID encryptionKeyUuid;

  @ManyToOne
  @JoinColumn(name = "secret_name_uuid", nullable = false)
  private SecretName secretName;

  public NamedSecretData(SecretName name) {
    if (this.secretName != null) {
      this.secretName.setName(name.getName());
    } else {
      setSecretName(name);
    }
  }

  public NamedSecretData(String name) {
    this(new SecretName(name));
  }

  public NamedSecretData() {
    this((String) null);
  }

  public UUID getUuid() {
    return uuid;
  }

  public Z setUuid(UUID uuid) {
    this.uuid = uuid;
    return (Z) this;
  }

  public SecretName getSecretName() {
    return secretName;
  }

  public void setSecretName(SecretName secretName) {
    this.secretName = secretName;
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

  public abstract SecretKind getKind();

  public abstract String getSecretType();

  public UUID getEncryptionKeyUuid() {
    return encryptionKeyUuid;
  }

  public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    this.encryptionKeyUuid = encryptionKeyUuid;
  }

  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    this.versionCreatedAt = versionCreatedAt;
    return (Z) this;
  }

  public static Stream<String> fullHierarchyForPath(String path) {
    String[] components = path.split("/");
    if (components.length > 1) {
      StringBuilder currentPath = new StringBuilder();
      List<String> pathSet = new ArrayList<>();
      for (int i = 0; i < components.length - 1; i++) {
        String element = components[i];
        currentPath.append(element).append('/');
        pathSet.add(currentPath.toString());
      }
      return pathSet.stream();
    } else {
      return Stream.of();
    }
  }

  abstract void copyIntoImpl(Z copy);

  public void copyInto(Z copy) {
    copy.setSecretName(getSecretName());
    copy.setEncryptedValue(encryptedValue);
    copy.setNonce(nonce);
    copy.setEncryptionKeyUuid(encryptionKeyUuid);
    copyIntoImpl(copy);
  }
}
