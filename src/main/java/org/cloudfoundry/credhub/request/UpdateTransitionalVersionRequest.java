package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;

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
}
