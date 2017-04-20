package io.pivotal.security.entity;

import org.apache.commons.lang3.StringUtils;
import org.hibernate.annotations.GenericGenerator;

import java.util.List;
import java.util.UUID;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "CredentialName")
public class CredentialName {

  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(unique = true, nullable = false)
  private String name;

  @OneToMany(mappedBy = "credentialName", cascade = CascadeType.ALL)
  private List<AccessEntryData> accessControlList;

  // Needed for hibernate
  @SuppressWarnings("unused")
  CredentialName() {
    this(null);
  }

  public CredentialName(String name) {
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

  public List<AccessEntryData> getAccessControlList() {
    return accessControlList;
  }

  public void setAccessControlList(List<AccessEntryData> accessControlList) {
    this.accessControlList = accessControlList;
  }
}
