package org.cloudfoundry.credhub.audit.entity;

import java.util.List;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.request.PermissionEntry;

public class AddPermission implements RequestDetails {

  private String credentialName;
  private List<PermissionEntry> permissions;

  public AddPermission() {
    super();

  }
  public AddPermission(final String credentialName, final List<PermissionEntry> permissions) {
    super();
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(final String credentialName) {
    this.credentialName = credentialName;
  }

  public List<PermissionEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(final List<PermissionEntry> permissions) {
    this.permissions = permissions;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.ADD_PERMISSIONS;
  }
}
