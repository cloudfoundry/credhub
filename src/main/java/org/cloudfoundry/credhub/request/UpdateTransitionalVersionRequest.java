package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateTransitionalVersionRequest {
  @JsonProperty("version")
  private String versionUuid;

  public UpdateTransitionalVersionRequest() {
  }

  public UpdateTransitionalVersionRequest(String versionUuid) {
    this.versionUuid = versionUuid;
  }

  public String getVersionUuid() {
    return versionUuid;
  }

  public void setVersionUuid(String versionUuid) {
    this.versionUuid = versionUuid;
  }
}
