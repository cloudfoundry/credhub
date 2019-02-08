package org.cloudfoundry.credhub.audit.entities;

import java.util.Objects;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.RequestDetails;

public class GetCredential implements RequestDetails {
  private String name;
  private Integer versions;
  private Boolean current;

  public GetCredential(final String credentialName, final Integer numberOfVersions, final boolean current) {
    super();
    name = credentialName;
    versions = numberOfVersions;
    this.current = current;
  }

  public GetCredential() {
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

    final GetCredential that = (GetCredential) o;

    return new EqualsBuilder()
      .append(name, that.name)
      .append(versions, that.versions)
      .append(current, that.current)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, versions, current);
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GET;
  }

  public String getName() {
    return name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  public Integer getVersions() {
    return versions;
  }

  public void setVersions(final Integer versions) {
    this.versions = versions;
  }

  public Boolean getCurrent() {
    return current;
  }

  public void setCurrent(final Boolean current) {
    this.current = current;
  }
}
