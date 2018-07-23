package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.cloudfoundry.credhub.request.PermissionOperation;

import java.util.List;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsV2View {

  private String path;
  private List<PermissionOperation> operations;
  private String actor;


  public PermissionsV2View(String path, List<PermissionOperation> operations, String actor) {
    this.path = path;
    this.operations = operations;
    this.actor = actor;
  }

  public PermissionsV2View() {
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
}
