package org.cloudfoundry.credhub.audit.entity;

import java.util.Objects;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class GetCredential implements RequestDetails {
  private String name;
  private Integer versions;
  private Boolean current;
  private CEFAuditRecord auditRecord;

  public GetCredential(String credentialName, Integer numberOfVersions, boolean current) {
    name = credentialName;
    versions = numberOfVersions;
    this.current = current;
  }

  public GetCredential() {

  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    GetCredential that = (GetCredential) o;

    return new EqualsBuilder()
      .append(name, that.name)
      .append(versions, that.versions)
      .append(current, that.current)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, versions, current, auditRecord);
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.GET;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Integer getVersions() {
    return versions;
  }

  public void setVersions(Integer versions) {
    this.versions = versions;
  }

  public Boolean getCurrent() {
    return current;
  }

  public void setCurrent(Boolean current) {
    this.current = current;
  }
}
