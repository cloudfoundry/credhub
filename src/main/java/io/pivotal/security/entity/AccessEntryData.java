package io.pivotal.security.entity;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

import io.pivotal.security.request.AccessControlOperation;
import java.util.ArrayList;
import java.util.List;
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
  @JoinColumn(name = "credential_name_uuid", nullable = false)
  private CredentialName credentialName;

  @Column(nullable = false)
  private String actor;

  @Column(name = "read_permission", nullable = false)
  private Boolean readPermission = DEFAULT_DENY;

  @Column(name = "write_permission", nullable = false)
  private Boolean writePermission = DEFAULT_DENY;

  @Column(name = "delete_permission", nullable = false)
  private Boolean deletePermission = DEFAULT_DENY;

  @Column(name = "read_acl_permission", nullable = false)
  private Boolean readAclPermission = DEFAULT_DENY;

  @Column(name = "write_acl_permission", nullable = false)
  private Boolean writeAclPermission = DEFAULT_DENY;

  @SuppressWarnings("unused")
  public AccessEntryData() {
    this(null, null, new ArrayList<>());
  }

  public AccessEntryData(CredentialName credentialName, String actor,
                         List<AccessControlOperation> operations) {
    this(credentialName, actor);
    enableOperations(operations);
  }

  public AccessEntryData(CredentialName credentialName, String actor) {
    this.credentialName = credentialName;
    this.actor = actor;
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public CredentialName getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(CredentialName credentialName) {
    this.credentialName = credentialName;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  public Boolean hasReadPermission() {
    return readPermission;
  }

  public Boolean hasWritePermission() {
    return writePermission;
  }

  public Boolean hasDeletePermission() {
    return deletePermission;
  }

  public Boolean hasWriteAclPermission() {
    return writeAclPermission;
  }

  public Boolean hasReadAclPermission() {
    return readAclPermission;
  }

  public void enableOperations(Iterable<AccessControlOperation> operations) {
    for (AccessControlOperation operation : operations) {
      enableOperation(operation);
    }
  }

  public List<AccessControlOperation> generateAccessControlOperations() {
    List<AccessControlOperation> operations = new ArrayList<>();

    if (hasReadPermission()) {
      operations.add(AccessControlOperation.READ);
    }
    if (hasWritePermission()) {
      operations.add(AccessControlOperation.WRITE);
    }
    if (hasDeletePermission()) {
      operations.add(AccessControlOperation.DELETE);
    }
    if (hasReadAclPermission()) {
      operations.add(AccessControlOperation.READ_ACL);
    }
    if (hasWriteAclPermission()) {
      operations.add(AccessControlOperation.WRITE_ACL);
    }
    return operations;
  }

  private void setReadPermission(Boolean readPermission) {
    this.readPermission = readPermission;
  }

  private void setWritePermission(Boolean writePermission) {
    this.writePermission = writePermission;
  }

  private void setDeletePermission(Boolean deletePermission) {
    this.deletePermission = deletePermission;
  }

  private void setReadAclPermission(Boolean readAclPermission) {
    this.readAclPermission = readAclPermission;
  }

  private void setWriteAclPermission(Boolean writeAclPermission) {
    this.writeAclPermission = writeAclPermission;
  }

  private void enableOperation(AccessControlOperation operation) {
    switch (operation) {
      case READ:
        setReadPermission(true);
        break;
      case WRITE:
        setWritePermission(true);
        break;
      case DELETE:
        setDeletePermission(true);
        break;
      case WRITE_ACL:
        setWriteAclPermission(true);
        break;
      case READ_ACL:
        setReadAclPermission(true);
        break;
      default:
        throw new RuntimeException();
    }
  }
}
