package org.cloudfoundry.credhub.data;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.AuditablePermissionData;
import org.cloudfoundry.credhub.constants.UuidConstants;
import org.hibernate.annotations.GenericGenerator;

import static org.cloudfoundry.credhub.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.PermissionOperation.READ;
import static org.cloudfoundry.credhub.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL;

@Entity
@Table(name = "permission")
@SuppressWarnings("PMD.TooManyMethods")
public class PermissionData implements AuditablePermissionData {

  private static final boolean DEFAULT_DENY = false;

  @Id
  @Column(length = UuidConstants.UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(nullable = false)
  private String path;

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

  public PermissionData(final String path, final String actor,
                        final List<PermissionOperation> operations) {
    this(path, actor);
    enableOperations(operations);
  }

  public PermissionData(final String path, final String actor) {
    super();
    this.path = path;
    this.actor = actor;
  }

  @Override
  public UUID getUuid() {
    return uuid;
  }

  @Override
  public void setUuid(final UUID uuid) {
    this.uuid = uuid;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(final String actor) {
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

  public boolean hasPermission(final PermissionOperation requiredPermission) {
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

  public void enableOperations(final Iterable<PermissionOperation> operations) {
    for (final PermissionOperation operation : operations) {
      enableOperation(operation);
    }
  }

  public List<PermissionOperation> generateAccessControlOperations() {
    final List<PermissionOperation> operations = new ArrayList<>();

    if (hasReadPermission()) {
      operations.add(READ);
    }
    if (hasWritePermission()) {
      operations.add(WRITE);
    }
    if (hasDeletePermission()) {
      operations.add(DELETE);
    }
    if (hasReadAclPermission()) {
      operations.add(READ_ACL);
    }
    if (hasWriteAclPermission()) {
      operations.add(WRITE_ACL);
    }
    return operations;
  }

  private void setReadPermission(final boolean readPermission) {
    this.readPermission = readPermission;
  }

  private void setWritePermission(final boolean writePermission) {
    this.writePermission = writePermission;
  }

  private void setDeletePermission(final boolean deletePermission) {
    this.deletePermission = deletePermission;
  }

  private void setReadAclPermission(final boolean readAclPermission) {
    this.readAclPermission = readAclPermission;
  }

  private void setWriteAclPermission(final boolean writeAclPermission) {
    this.writeAclPermission = writeAclPermission;
  }

  private void enableOperation(final PermissionOperation operation) {
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

  @Override
  public String getPath() {
    return path;
  }

  @Override
  public void setPath(final String path) {
    this.path = path;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final PermissionData that = (PermissionData) o;
    return readPermission == that.readPermission &&
      writePermission == that.writePermission &&
      deletePermission == that.deletePermission &&
      readAclPermission == that.readAclPermission &&
      writeAclPermission == that.writeAclPermission &&
      Objects.equals(uuid, that.uuid) &&
      Objects.equals(path, that.path) &&
      Objects.equals(actor, that.actor);
  }

  @Override
  public int hashCode() {
    return Objects.hash(uuid, path, actor, readPermission, writePermission, deletePermission, readAclPermission, writeAclPermission);
  }
}
