package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonAutoDetect
@SuppressWarnings("unused")
public class CertificateRegenerateRequest {

  public CertificateRegenerateRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public CertificateRegenerateRequest(boolean transitional) {
    this.transitional = transitional;
  }

  @JsonProperty("set_as_transitional")
  private boolean transitional;

  public boolean isTransitional() {
    return transitional;
  }

  @JsonProperty("set_as_transitional")
  public void setTransitional(boolean transitional) {
    this.transitional = transitional;
  }

}
