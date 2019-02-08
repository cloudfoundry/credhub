package org.cloudfoundry.credhub.views;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.cloudfoundry.credhub.requests.PermissionEntry;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsView {

  private String credentialName;
  private List<PermissionEntry> permissions;

  public PermissionsView() {
    super();
  }

  public PermissionsView(final String credentialName,
                         final List<PermissionEntry> permissions) {
    super();
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(final String credentialName) {
    this.credentialName = credentialName;
  }

  public List<PermissionEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(final List<PermissionEntry> permissions) {
    this.permissions = permissions;
  }
}
