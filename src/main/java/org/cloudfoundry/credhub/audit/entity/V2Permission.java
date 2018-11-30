package org.cloudfoundry.credhub.audit.entity;

import java.util.List;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.request.PermissionOperation;

public class V2Permission implements RequestDetails {
  private String path;
  private String actor;
  private List<PermissionOperation> operations;
  private OperationDeviceAction action;
  public V2Permission() {

  }
  public V2Permission(String path, String actor, List<PermissionOperation> operations,
                      OperationDeviceAction action) {
    this.path = path;
    this.actor = actor;
    this.operations = operations;
    this.action = action;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public List<PermissionOperation> getOperations() {
    return operations;
  }

  public void setOperations(List<PermissionOperation> operations) {
    this.operations = operations;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  @Override
  public OperationDeviceAction operation() {
    return action;
  }
}
