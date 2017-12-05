package org.cloudfoundry.credhub.entity;

import org.hibernate.annotations.GenericGenerator;

import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import static org.cloudfoundry.credhub.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "credential")
public class Credential {

  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(unique = true, nullable = false)
  private String name;

  // Needed for hibernate
  @SuppressWarnings("unused")
  Credential() {
    this(null);
  }

  public Credential(String name) {
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
    this.name = name;
  }

}
