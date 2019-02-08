package org.cloudfoundry.credhub.audit.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

@JsonIgnoreProperties(ignoreUnknown = true)
public class InterpolateCredentials implements RequestDetails {

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.INTERPOLATE;
  }
}
