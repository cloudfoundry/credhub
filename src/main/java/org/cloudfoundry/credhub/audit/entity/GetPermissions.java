package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GetPermissions implements RequestDetails {

  public GetPermissions() {

  }

  public GetPermissions(String credentialName) {
    this.credentialName = credentialName;
  }

  private String credentialName;

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
