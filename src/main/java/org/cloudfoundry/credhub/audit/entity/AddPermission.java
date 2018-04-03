package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.request.PermissionEntry;

import java.util.List;

public class AddPermission implements RequestDetails {

  public AddPermission() {

  }

  public AddPermission(String credentialName, List<PermissionEntry> permissions) {
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  private String credentialName;
  private List<PermissionEntry> permissions;

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public List<PermissionEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<PermissionEntry> permissions) {
    this.permissions = permissions;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.ADD_PERMISSION;
  }
}
