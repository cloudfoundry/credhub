package org.cloudfoundry.credhub.audit.entities;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class DeletePermissions implements RequestDetails {

  private String credentialName;
  private String actor;

  public DeletePermissions() {
    super();

  }
  public DeletePermissions(final String credentialName, final String actor) {
    super();
    this.credentialName = credentialName;
    this.actor = actor;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(final String credentialName) {
    this.credentialName = credentialName;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(final String actor) {
    this.actor = actor;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.DELETE_PERMISSIONS;
  }
}
