package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class CreateVersionRequest {

  public CreateVersionRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public CreateVersionRequest(CertificateCredentialValue value, boolean transitional) {
    this.value = value;
    this.transitional = transitional;
  }

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private CertificateCredentialValue value;

  @JsonProperty("transitional")
  private boolean transitional;

  public boolean isTransitional() {
    return transitional;
  }

  public void setTransitional(boolean transitional) {
    this.transitional = transitional;
  }

  public CertificateCredentialValue getValue() {
    return value;
  }

  public void setValue(CertificateCredentialValue value) {
    this.value = value;
  }
}
