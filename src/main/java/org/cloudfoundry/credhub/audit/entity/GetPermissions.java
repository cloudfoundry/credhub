package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GetPermissions implements RequestDetails {

  private String credentialName;

  public GetPermissions() {
    super();

  }

  public GetPermissions(final String credentialName) {
    super();
    this.credentialName = credentialName;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(final String credentialName) {
    this.credentialName = credentialName;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GET_PERMISSIONS;
  }
}
