package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@JsonAutoDetect
@Validated
public class PermissionEntry {

  @NotEmpty(message = "error.acl.missing_actor")
  private String actor;

  @NotEmpty(message = "error.acl.missing_operations")
  @JsonProperty("operations")
  private List<PermissionOperation> allowedOperations;

  public PermissionEntry() {
  }

  public PermissionEntry(String actor, List<PermissionOperation> operations) {
    this.actor = actor;
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
}
