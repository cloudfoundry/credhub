package org.cloudfoundry.credhub.views;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
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

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PermissionsView that = (PermissionsView) o;

    return new EqualsBuilder()
      .append(credentialName, that.credentialName)
      .append(permissions, that.permissions)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
      .append(credentialName)
      .append(permissions)
      .toHashCode();
  }
}
