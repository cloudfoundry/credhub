package org.cloudfoundry.credhub.audit.entities;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class FindCredential implements RequestDetails {
  private String nameLike;
  private String path;
  private Boolean paths;

  private String expiresWithinDays;

  public String getExpiresWithinDays() {
    return expiresWithinDays;
  }

  public void setExpiresWithinDays(final String expiresWithinDays) {
    this.expiresWithinDays = expiresWithinDays;
  }

  public String getNameLike() {
    return nameLike;
  }

  public void setNameLike(final String nameLike) {
    this.nameLike = nameLike;
  }

  public String getPath() {
    return path;
  }

  public void setPath(final String path) {
    this.path = path;
  }

  public Boolean getPaths() {
    return paths;
  }

  public void setPaths(final Boolean paths) {
    this.paths = paths;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.FIND;
  }
}
