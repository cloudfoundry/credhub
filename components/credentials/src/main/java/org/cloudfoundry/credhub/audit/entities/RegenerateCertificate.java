package org.cloudfoundry.credhub.audit.entities;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class RegenerateCertificate implements RequestDetails {
  private Boolean transitional;

  public Boolean getTransitional() {
    return transitional;
  }

  public void setTransitional(final Boolean transitional) {
    this.transitional = transitional;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.REGENERATE_CERTIFICATE;
  }
}
