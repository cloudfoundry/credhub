package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class FindCredential implements RequestDetails {
  private String nameLike, path;
  private Boolean paths;

  public String getNameLike() {
    return nameLike;
  }

  public void setNameLike(String nameLike) {
    this.nameLike = nameLike;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public Boolean getPaths() {
    return paths;
  }

  public void setPaths(Boolean paths) {
    this.paths = paths;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.FIND;
  }
}
