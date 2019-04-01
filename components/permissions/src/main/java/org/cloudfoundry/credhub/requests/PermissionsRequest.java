package org.cloudfoundry.credhub.requests;

import java.util.List;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.cloudfoundry.credhub.ErrorMessages;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsRequest {

  @NotEmpty(message = ErrorMessages.MISSING_NAME)
  private String credentialName;
  @NotEmpty(message = ErrorMessages.Permissions.MISSING_ACES)
  private List<PermissionEntry> permissions;

  public PermissionsRequest() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public PermissionsRequest(final String credentialName, final List<PermissionEntry> permissions) {
    super();
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(final String credentialName) {
    this.credentialName = StringUtils.prependIfMissing(credentialName, "/");
  }

  public List<PermissionEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(final List<PermissionEntry> permissions) {
    this.permissions = permissions;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final PermissionsRequest that = (PermissionsRequest) o;

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
