package org.cloudfoundry.credhub.entity;

import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.constants.UuidConstants;
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

@Entity
@Table(name = "permission")
public class PermissionData {

  private static final boolean DEFAULT_DENY = false;

  @Id
  @Column(length = UuidConstants.UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @ManyToOne
  @JoinColumn(name = "credential_uuid", nullable = false)
  private Credential credential;

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
  public PermissionData() {
    this(null, null, new ArrayList<>());
  }

  public PermissionData(Credential credential, String actor,
                        List<PermissionOperation> operations) {
    this(credential, actor);
    enableOperations(operations);
  }

  public PermissionData(Credential credential, String actor) {
    this.credential = credential;
    this.actor = actor;
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public Credential getCredential() {
    return credential;
  }

  public void setCredential(Credential credential) {
    this.credential = credential;
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

  public boolean hasPermission(PermissionOperation requiredPermission) {
    switch (requiredPermission) {
      case READ:
        return hasReadPermission();
      case WRITE:
        return hasWritePermission();
      case DELETE:
        return hasDeletePermission();
      case READ_ACL:
        return hasReadAclPermission();
      case WRITE_ACL:
        return hasWriteAclPermission();
      default:
        return false;
    }
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
