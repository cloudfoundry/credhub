package org.cloudfoundry.credhub.request;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
public class PermissionsV2PatchRequest {
  private List<PermissionOperation> operations;

  public List<PermissionOperation> getOperations() {
    return operations;
  }

  public void setOperations(final List<PermissionOperation> operations) {
    this.operations = operations;
  }
}
