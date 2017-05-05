package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import io.pivotal.security.request.AccessControlEntry;
import java.util.List;

@JsonAutoDetect
@SuppressWarnings("unused")
public class AccessControlListResponse {

  private String credentialName;
  private List<AccessControlEntry> accessControlList;

  public AccessControlListResponse() {
  }

  public AccessControlListResponse(String credentialName,
      List<AccessControlEntry> accessControlList) {
    this.credentialName = credentialName;
    this.accessControlList = accessControlList;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public List<AccessControlEntry> getAccessControlList() {
    return accessControlList;
  }

  public void setAccessControlList(List<AccessControlEntry> accessControlList) {
    this.accessControlList = accessControlList;
  }
}
