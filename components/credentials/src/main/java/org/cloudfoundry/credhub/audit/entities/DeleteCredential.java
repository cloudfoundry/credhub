package org.cloudfoundry.credhub.audit.entities;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class DeleteCredential implements RequestDetails {
  private String name;

  public DeleteCredential() {
    super();

  }

  public DeleteCredential(final String name) {
    super();
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.DELETE;
  }
}
