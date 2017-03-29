package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import java.util.List;
import javax.validation.Valid;
import org.hibernate.validator.constraints.NotEmpty;

@JsonAutoDetect
@SuppressWarnings("unused")
public class AccessEntryRequest {

  @NotEmpty(message = "error.missing_name")
  private String credentialName;
  @NotEmpty(message = "error.acl.missing_aces")
  private List<AccessControlEntry> accessControlEntries;

  public AccessEntryRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public AccessEntryRequest(String credentialName, List<AccessControlEntry> accessControlEntries) {
    this.credentialName = credentialName;
    this.accessControlEntries = accessControlEntries;
  }

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
