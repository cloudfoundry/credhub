package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@JsonAutoDetect
@Validated
public class AccessControlEntry {

  @NotEmpty(message = "error.acl.missing_actor")
  private String actor;

  @NotEmpty(message = "error.acl.missing_operations")
//  @EachPattern(regexp = "(read|write)", message = "error.acl.invalid_operation")
  private List<AccessControlOperation> operations;

  public AccessControlEntry() {
  }

  public AccessControlEntry(String actor, List<AccessControlOperation> operations) {
    this.actor = actor;
    this.operations = operations;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  public List<AccessControlOperation> getOperations() {
    return operations;
  }

  public void setOperations(List<AccessControlOperation> operations) {
    this.operations = operations;
  }
}
