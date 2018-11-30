package org.cloudfoundry.credhub.view;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.cloudfoundry.credhub.request.PermissionOperation;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsV2View {

  private String path;
  private List<PermissionOperation> operations;
  private String actor;
  private UUID uuid;

  public PermissionsV2View(String path, List<PermissionOperation> operations, String actor, UUID uuid) {
    this.path = path;
    this.operations = operations;
    this.actor = actor;
    this.uuid = uuid;
  }

  public PermissionsV2View() {
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
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
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PermissionsV2View that = (PermissionsV2View) o;
    return Objects.equals(path, that.path) &&
      Objects.equals(operations, that.operations) &&
      Objects.equals(actor, that.actor) &&
      Objects.equals(uuid, that.uuid);
  }

  @Override
  public int hashCode() {
    return Objects.hash(path, operations, actor, uuid);
  }
}
