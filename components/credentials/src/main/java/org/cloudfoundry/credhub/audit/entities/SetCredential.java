package org.cloudfoundry.credhub.audit.entities;

import java.util.Objects;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class SetCredential implements RequestDetails {
  private String name;
  private String type;

  public SetCredential(final String credentialName, final String credentialType) {
    super();
    name = credentialName;
    type = credentialType;
  }

  public SetCredential() {
    super();

  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final SetCredential that = (SetCredential) o;

    return new EqualsBuilder()
      .append(name, that.name)
      .append(type, that.type)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, type);
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.SET;
  }

  public String getName() {
    return name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(final String type) {
    this.type = type;
  }
}
