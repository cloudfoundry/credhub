package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class DeletePermissions implements RequestDetails {

  public DeletePermissions() {

  }

  public DeletePermissions(String credentialName, String actor) {
    this.credentialName = credentialName;
    this.actor = actor;
  }

  private String credentialName;
  private String actor;

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.DELETE_PERMISSIONS;
  }
}
