package org.cloudfoundry.credhub.audit.entities;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class UpdateTransitionalVersion implements RequestDetails {
  private String version;


  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.UPDATE_TRANSITIONAL_VERSION;
  }

  public String getVersion() {
    return version;
  }

  public void setVersion(final String version) {
    this.version = version;
  }
}
