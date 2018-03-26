package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GetCredentialById implements RequestDetails {
  private String uuid;

  public GetCredentialById(String uuid){
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
