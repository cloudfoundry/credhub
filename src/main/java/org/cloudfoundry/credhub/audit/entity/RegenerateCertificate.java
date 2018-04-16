package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class RegenerateCertificate implements RequestDetails {
  private Boolean transitional;

  public Boolean getTransitional() {
    return transitional;
  }

  public void setTransitional(Boolean transitional) {
    this.transitional = transitional;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.REGENERATE_CERTIFICATE;
  }
}
