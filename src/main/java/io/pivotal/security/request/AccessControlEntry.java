package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.validation.annotation.Validated;

@JsonAutoDetect
@Validated
public class AccessControlEntry {

  @NotEmpty(message = "error.acl.missing_actor")
  private String actor;

  @NotEmpty(message = "error.acl.missing_operations")
  @JsonProperty("operations")
  private List<AccessControlOperation> allowedOperations;

  public AccessControlEntry() {
  }

  public AccessControlEntry(String actor, List<AccessControlOperation> operations) {
    this.actor = actor;
    this.allowedOperations = operations;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String actor) {
    this.actor = actor;
  }

  public List<AccessControlOperation> getAllowedOperations() {
    return allowedOperations;
  }

  public void setAllowedOperations(List<AccessControlOperation> allowedOperations) {
    this.allowedOperations = allowedOperations;
  }
}
