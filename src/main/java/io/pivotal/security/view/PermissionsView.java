package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import io.pivotal.security.request.PermissionEntry;
import java.util.List;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsView {

  private String credentialName;
  private List<PermissionEntry> permissions;

  public PermissionsView() {
  }

  public PermissionsView(String credentialName,
      List<PermissionEntry> permissions) {
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public List<PermissionEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<PermissionEntry> permissions) {
    this.permissions = permissions;
  }
}
