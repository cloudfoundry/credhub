package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonAutoDetect
@SuppressWarnings("unused")
public class CertificateRegenerateRequest {

  @JsonProperty("set_as_transitional")
  private boolean transitional;

  public CertificateRegenerateRequest() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public CertificateRegenerateRequest(final boolean transitional) {
    super();
    this.transitional = transitional;
  }

  public boolean isTransitional() {
    return transitional;
  }

  @JsonProperty("set_as_transitional")
  public void setTransitional(final boolean transitional) {
    this.transitional = transitional;
  }

}
