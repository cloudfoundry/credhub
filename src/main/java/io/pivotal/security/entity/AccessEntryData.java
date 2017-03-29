package io.pivotal.security.entity;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(name = "AccessEntry")
public class AccessEntryData {

  private static final boolean DEFAULT_DENY = false;

  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @ManyToOne
  @JoinColumn(name = "secret_name_uuid", nullable = false)
  private SecretName credentialName;

  @Column(nullable = false)
  private String actor;

  @Column(name = "read_permission", nullable = false)
  private Boolean readPermission = DEFAULT_DENY;

  @Column(name = "write_permission", nullable = false)
  private Boolean writePermission = DEFAULT_DENY;

  @SuppressWarnings("unused")
  public AccessEntryData() {
    this(null, null, new ArrayList<>());
  }

  public AccessEntryData(SecretName secretName, String actor,
      List<AccessControlOperation> operations) {
    this(secretName, actor);
    enableOperations(operations);
  }

  public AccessEntryData(SecretName secretName, AccessControlEntry accessControlEntry) {
    this(secretName, accessControlEntry.getActor());
    enableOperations(accessControlEntry.getAllowedOperations());
  }

  public AccessEntryData(SecretName credentialName, String actor) {
    this.credentialName = credentialName;
    this.actor = actor;
  }

  public static AccessEntryData fromSecretName(SecretName secretName,
      AccessControlEntry accessControlEntry) {
    if (secretName.getAccessControlList() == null) {
      return new AccessEntryData(secretName, accessControlEntry);
    }
    Optional<AccessEntryData> accessEntryDataOptional = secretName.getAccessControlList().stream()
        .filter((entry) -> accessControlEntry.getActor().equals(entry.getActor())).findFirst();
    if (accessEntryDataOptional.isPresent()) {
      AccessEntryData entryData = accessEntryDataOptional.get();
      entryData.enableOperations(accessControlEntry.getAllowedOperations());
      return entryData;
    } else {
      return new AccessEntryData(secretName, accessControlEntry);
    }
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public SecretName getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(SecretName credentialName) {
    this.credentialName = credentialName;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  public Boolean getReadPermission() {
    return readPermission;
  }

  public void setReadPermission(Boolean readPermission) {
    this.readPermission = readPermission;
  }

  public Boolean getWritePermission() {
    return writePermission;
  }

  public void setWritePermission(Boolean writePermission) {
    this.writePermission = writePermission;
  }

  public void enableOperation(AccessControlOperation operation) {
    switch (operation) {
      case READ:
        setReadPermission(true);
        break;
      case WRITE:
        setWritePermission(true);
        break;
      default:
        throw new RuntimeException();
    }
  }

  public void enableOperations(Iterable<AccessControlOperation> operations) {
    for (AccessControlOperation operation : operations) {
      enableOperation(operation);
    }
  }

  public List<AccessControlOperation> generateAccessControlOperations() {
    List<AccessControlOperation> operations = new ArrayList<>();
    if (getReadPermission()) {
      operations.add(AccessControlOperation.READ);
    }
    if (getWritePermission()) {
      operations.add(AccessControlOperation.WRITE);
    }
    return operations;
  }
}
