package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class UpdateTransitionalVersion implements RequestDetails {
  private String version;


  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.UPDATE_TRANSITIONAL_VERSION;
  }

  public String getVersion() {
    return version;
  }

  public void setVersion(String version) {
    this.version = version;
  }
}
