package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.List;
import javax.validation.Valid;

@JsonAutoDetect
@SuppressWarnings("unused")
public class AccessEntriesRequest {

  @NotEmpty(message = "error.missing_name")
  private String credentialName;
  @NotEmpty(message = "error.acl.missing_aces")
  private List<AccessControlEntry> permissions;

  public AccessEntriesRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public AccessEntriesRequest(String credentialName, List<AccessControlEntry> permissions) {
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  @Valid
  public List<AccessControlEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<AccessControlEntry> permissions) {
    this.permissions = permissions;
  }
}
