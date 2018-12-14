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
    super();

  }
  public V2Permission(final String path, final String actor, final List<PermissionOperation> operations,
                      final OperationDeviceAction action) {
    super();
    this.path = path;
    this.actor = actor;
    this.operations = operations;
    this.action = action;
  }

  public String getPath() {
    return path;
  }

  public void setPath(final String path) {
    this.path = path;
  }

  public List<PermissionOperation> getOperations() {
    return operations;
  }

  public void setOperations(final List<PermissionOperation> operations) {
    this.operations = operations;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(final String actor) {
    this.actor = actor;
  }

  @Override
  public OperationDeviceAction operation() {
    return action;
  }
}
