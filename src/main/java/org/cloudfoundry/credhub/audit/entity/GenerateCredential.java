package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GenerateCredential extends SetCredential {
  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GENERATE;
  }
}
