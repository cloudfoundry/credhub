package io.pivotal.security.entity;

import io.pivotal.security.request.PermissionOperation;
import org.hibernate.annotations.GenericGenerator;

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

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

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
  private boolean readPermission = DEFAULT_DENY;

  @Column(name = "write_permission", nullable = false)
  private boolean writePermission = DEFAULT_DENY;

  @Column(name = "delete_permission", nullable = false)
  private boolean deletePermission = DEFAULT_DENY;

  @Column(name = "read_acl_permission", nullable = false)
  private boolean readAclPermission = DEFAULT_DENY;

  @Column(name = "write_acl_permission", nullable = false)
  private boolean writeAclPermission = DEFAULT_DENY;

  @SuppressWarnings("unused")
  public AccessEntryData() {
    this(null, null, new ArrayList<>());
  }

  public AccessEntryData(CredentialName credentialName, String actor,
                         List<PermissionOperation> operations) {
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

  public boolean hasReadPermission() {
    return readPermission;
  }

  public boolean hasWritePermission() {
    return writePermission;
  }

  public boolean hasDeletePermission() {
    return deletePermission;
  }

  public boolean hasWriteAclPermission() {
    return writeAclPermission;
  }

  public boolean hasReadAclPermission() {
    return readAclPermission;
  }

  public void enableOperations(Iterable<PermissionOperation> operations) {
    for (PermissionOperation operation : operations) {
      enableOperation(operation);
    }
  }

  public List<PermissionOperation> generateAccessControlOperations() {
    List<PermissionOperation> operations = new ArrayList<>();

    if (hasReadPermission()) {
      operations.add(PermissionOperation.READ);
    }
    if (hasWritePermission()) {
      operations.add(PermissionOperation.WRITE);
    }
    if (hasDeletePermission()) {
      operations.add(PermissionOperation.DELETE);
    }
    if (hasReadAclPermission()) {
      operations.add(PermissionOperation.READ_ACL);
    }
    if (hasWriteAclPermission()) {
      operations.add(PermissionOperation.WRITE_ACL);
    }
    return operations;
  }

  private void setReadPermission(boolean readPermission) {
    this.readPermission = readPermission;
  }

  private void setWritePermission(boolean writePermission) {
    this.writePermission = writePermission;
  }

  private void setDeletePermission(boolean deletePermission) {
    this.deletePermission = deletePermission;
  }

  private void setReadAclPermission(boolean readAclPermission) {
    this.readAclPermission = readAclPermission;
  }

  private void setWriteAclPermission(boolean writeAclPermission) {
    this.writeAclPermission = writeAclPermission;
  }

  private void enableOperation(PermissionOperation operation) {
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
