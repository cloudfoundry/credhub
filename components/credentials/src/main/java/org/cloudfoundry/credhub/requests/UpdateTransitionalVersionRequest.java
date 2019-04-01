package org.cloudfoundry.credhub.requests;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class UpdateTransitionalVersionRequest {
  @JsonProperty("version")
  private String versionUuid;

  public UpdateTransitionalVersionRequest() {
    super();
  }

  public UpdateTransitionalVersionRequest(final String versionUuid) {
    super();
    this.versionUuid = versionUuid;
  }

  public String getVersionUuid() {
    return versionUuid;
  }

  public void setVersionUuid(final String versionUuid) {
    this.versionUuid = versionUuid;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final UpdateTransitionalVersionRequest that = (UpdateTransitionalVersionRequest) o;

    return new EqualsBuilder()
      .append(versionUuid, that.versionUuid)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
      .append(versionUuid)
      .toHashCode();
  }
}
