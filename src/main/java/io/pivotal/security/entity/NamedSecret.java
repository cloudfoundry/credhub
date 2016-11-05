package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

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
import javax.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_BYTES;
import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecret<Z extends NamedSecret> implements EncryptedValueContainer {
  // Use VARBINARY to make all 3 DB types happy.
  // H2 doesn't distinguish between "binary" and "varbinary" - see
  // https://hibernate.atlassian.net/browse/HHH-9835 and
  // https://github.com/h2database/h2database/issues/345
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(length = ENCRYPTED_BYTES + NONCE_BYTES, name = "encrypted_value")
  private byte[] encryptedValue;

  @Column(length = NONCE_BYTES)
  private byte[] nonce;

  @Convert(converter = InstantSecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  @LastModifiedDate
  private Instant updatedAt;

  public NamedSecret() {
    this(null);
  }

  public NamedSecret(String name) {
    setName(name);
  }

  public UUID getUuid() {
    return uuid;
  }

  public Z setUuid(UUID uuid) {
    this.uuid = uuid;
    return (Z) this;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
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

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public Z setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
    return (Z) this;
  }

  public abstract SecretKind getKind();

  public abstract String getSecretType();

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
    copy.setName(name);
    copy.setEncryptedValue(encryptedValue);
    copy.setNonce(nonce);
    copyIntoImpl(copy);
  }
}
