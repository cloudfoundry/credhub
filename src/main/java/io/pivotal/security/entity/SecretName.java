package io.pivotal.security.entity;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "SecretName")
public class SecretName {
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(unique = true, nullable = false)
  private String name;

  // Needed for hibernate
  @SuppressWarnings("unused")
  SecretName() {
    this(null);
  }

  public SecretName(String name) {
    setName(name);
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = StringUtils.prependIfMissing(name, "/");
  }
}
