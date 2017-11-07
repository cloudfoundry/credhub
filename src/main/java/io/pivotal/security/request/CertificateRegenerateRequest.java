package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
@SuppressWarnings("unused")
public class CertificateRegenerateRequest {

  public CertificateRegenerateRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public CertificateRegenerateRequest(boolean transitional) {
    this.transitional = transitional;
  }

  private boolean transitional;

  public boolean isTransitional() {
    return transitional;
  }

  public void setTransitional(boolean transitional) {
    this.transitional = transitional;
  }

}
