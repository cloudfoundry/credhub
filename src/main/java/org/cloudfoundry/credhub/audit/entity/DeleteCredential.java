package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class DeleteCredential implements RequestDetails {
  private String name;

  public DeleteCredential(){

  }

  public DeleteCredential(String name){
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.DELETE;
  }
}
