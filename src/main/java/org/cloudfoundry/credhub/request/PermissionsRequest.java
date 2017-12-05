package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.List;
import javax.validation.Valid;

@JsonAutoDetect
@SuppressWarnings("unused")
public class PermissionsRequest {

  @NotEmpty(message = "error.missing_name")
  private String credentialName;
  @NotEmpty(message = "error.permission.missing_aces")
  private List<PermissionEntry> permissions;

  public PermissionsRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public PermissionsRequest(String credentialName, List<PermissionEntry> permissions) {
    this.credentialName = credentialName;
    this.permissions = permissions;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = StringUtils.prependIfMissing(credentialName, "/");
  }

  @Valid
  public List<PermissionEntry> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<PermissionEntry> permissions) {
    this.permissions = permissions;
  }
}
