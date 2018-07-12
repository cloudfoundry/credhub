package org.cloudfoundry.credhub.request;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

@JsonAutoDetect
@Validated
public class PermissionEntry {
  @NotEmpty(message = "error.permission.missing_actor")
  private String actor;

  @NotEmpty(message = "error.permission.missing_path")
  private String path;

  @NotEmpty(message = "error.permission.missing_operations")
  @JsonProperty("operations")
  private List<PermissionOperation> allowedOperations;

  public PermissionEntry() {
  }

  public PermissionEntry(String actor, String path, PermissionOperation... operations) {
    this(actor, path, newArrayList(operations));
  }

  public PermissionEntry(String actor, String path, List<PermissionOperation> operations) {
    this.actor = actor;
    this.path = path;
    this.allowedOperations = operations;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  public List<PermissionOperation> getAllowedOperations() {
    return allowedOperations;
  }

  public void setAllowedOperations(List<PermissionOperation> allowedOperations) {
    this.allowedOperations = allowedOperations;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }
}
