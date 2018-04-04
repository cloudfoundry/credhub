package org.cloudfoundry.credhub.audit.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;

@JsonIgnoreProperties(ignoreUnknown=true)
public class InterpolateCredentials implements RequestDetails {

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.INTERPOLATE;
  }
}
