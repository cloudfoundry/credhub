package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import io.pivotal.security.request.AccessControlEntry;
import java.util.List;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsView {

  private String credentialName;
  private List<AccessControlEntry> permissions;

  public PermissionsView() {
  }

  public PermissionsView(String credentialName,
      List<AccessControlEntry> accessControlList) {
    this.credentialName = credentialName;
    this.permissions = accessControlList;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public List<AccessControlEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<AccessControlEntry> permissions) {
    this.permissions = permissions;
  }
}
