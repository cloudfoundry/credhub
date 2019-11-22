package org.cloudfoundry.credhub.audit.entities;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class GetAllCertificates implements RequestDetails {

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GET_ALL_CERTIFICATES;
  }
}
