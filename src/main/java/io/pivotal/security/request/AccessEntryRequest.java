package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.List;

import javax.validation.Valid;

@JsonAutoDetect
@SuppressWarnings("unused")
public class AccessEntryRequest {

  @NotEmpty(message = "error.missing_name")
  private String credentialName;

  public AccessEntryRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public AccessEntryRequest(String credentialName, List<AccessControlEntry> accessControlEntries) {
    this.credentialName = credentialName;
    this.accessControlEntries = accessControlEntries;
  }

  @NotEmpty(message = "error.acl.missing_aces")
  private List<AccessControlEntry> accessControlEntries;

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  @Valid
  public List<AccessControlEntry> getAccessControlEntries() {
    return accessControlEntries;
  }

  public void setAccessControlEntries(List<AccessControlEntry> accessControlEntries) {
    this.accessControlEntries = accessControlEntries;
  }
}
