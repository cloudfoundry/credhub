package org.cloudfoundry.credhub.requests;


import java.util.List;

import javax.validation.constraints.NotEmpty;

import org.springframework.validation.annotation.Validated;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.Lists;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;

@JsonAutoDetect
@Validated
public class PermissionEntry {
  @NotEmpty(message = ErrorMessages.Permissions.MISSING_ACTOR)
  private String actor;

  @NotEmpty(message = ErrorMessages.Permissions.MISSING_PATH)
  private String path;

  @NotEmpty(message = ErrorMessages.Permissions.MISSING_OPERATIONS)
  @JsonProperty("operations")
  private List<PermissionOperation> allowedOperations;

  public PermissionEntry() {
    super();
  }

  public PermissionEntry(final String actor, final String path, final PermissionOperation... operations) {
    this(actor, path, Lists.newArrayList(operations));
  }

  public PermissionEntry(final String actor, final String path, final List<PermissionOperation> operations) {
    super();
    this.actor = actor;
    this.path = path;
    this.allowedOperations = operations;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(final String actor) {
    this.actor = actor;
  }

  public List<PermissionOperation> getAllowedOperations() {
    return allowedOperations;
  }

  public void setAllowedOperations(final List<PermissionOperation> allowedOperations) {
    this.allowedOperations = allowedOperations;
  }

  public String getPath() {
    return path;
  }

  public void setPath(final String path) {
    this.path = path;
  }
}
