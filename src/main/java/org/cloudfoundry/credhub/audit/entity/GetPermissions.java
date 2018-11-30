package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GetPermissions implements RequestDetails {

  private String credentialName;

  public GetPermissions() {

  }

  public GetPermissions(String credentialName) {
    this.credentialName = credentialName;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GET_PERMISSIONS;
  }
}
