package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GetCredentialById implements RequestDetails {
  private final String uuid;

  public GetCredentialById(final String uuid) {
    super();
    this.uuid = uuid;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GET;
  }

  public String getUuid() {
    return uuid;
  }
}
