package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import javax.validation.constraints.NotEmpty;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsV2Request {
  @NotEmpty(message = "error.permission.missing_path")
  private String path;
  @NotEmpty(message = "error.permission.missing_actor")
  private String actor;
  private List<PermissionOperation> operations;

  public PermissionsV2Request() {
        /* this needs to be there for jackson to be happy */
  }

  public PermissionsV2Request(String path, String actor, List<PermissionOperation> operations) {
    this.path = path;
    this.actor = actor;
    this.operations = operations;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = StringUtils.prependIfMissing(path, "/");
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  public List<PermissionOperation> getOperations() {
    return operations;
  }

  public void setOperations(List<PermissionOperation> operations) {
    this.operations = operations;
  }
}
