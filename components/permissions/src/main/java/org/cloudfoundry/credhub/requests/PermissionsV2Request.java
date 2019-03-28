package org.cloudfoundry.credhub.requests;

import java.util.List;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsV2Request {
  @NotEmpty(message = ErrorMessages.Permissions.MISSING_PATH)
  private String path;
  @NotEmpty(message = ErrorMessages.Permissions.MISSING_ACTOR)
  private String actor;
  private List<PermissionOperation> operations;

  public PermissionsV2Request() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public PermissionsV2Request(final String path, final String actor, final List<PermissionOperation> operations) {
    super();
    this.path = path;
    this.actor = actor;
    this.operations = operations;
  }

  public String getPath() {
    return path;
  }

  public void setPath(final String path) {
    this.path = StringUtils.prependIfMissing(path, "/");
  }

  public String getActor() {
    return actor;
  }

  public void setActor(final String actor) {
    this.actor = actor;
  }

  public List<PermissionOperation> getOperations() {
    return operations;
  }

  public void setOperations(final List<PermissionOperation> operations) {
    this.operations = operations;
  }
}
