package org.cloudfoundry.credhub.audit.entity;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.request.PermissionEntry;

import java.util.List;

public class SetCredential implements RequestDetails {
  private String name;
  private String type;
  private CredentialWriteMode mode;
  private List<PermissionEntry> additionalPermissions;

  public SetCredential(String credentialName, String credentialType, CredentialWriteMode credentialMode, List<PermissionEntry> credentialAdditionalPermissions) {
    name = credentialName;
    type = credentialType;
    mode = credentialMode;
    additionalPermissions = credentialAdditionalPermissions;
  }

  public SetCredential(){

  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    SetCredential that = (SetCredential) o;

    return new EqualsBuilder()
        .append(name, that.name)
        .append(type, that.type)
        .append(mode, that.mode)
        .append(additionalPermissions, that.additionalPermissions)
        .isEquals();
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.SET;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() { return type; }

  public void setType(String type) { this.type = type; }

  public CredentialWriteMode getMode() { return mode; }

  public void setMode(CredentialWriteMode mode) { this.mode = mode; }

  public List<PermissionEntry> getAdditionalPermissions() { return additionalPermissions; }

  public void setAdditionalPermissions(List<PermissionEntry> additionalPermissions) {
    this.additionalPermissions = additionalPermissions;
  }

}
