package org.cloudfoundry.credhub.request;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;

public class CreateVersionRequest {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private CertificateCredentialValue value;
  @JsonProperty("transitional")
  private boolean transitional;

  public CreateVersionRequest() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public CreateVersionRequest(final CertificateCredentialValue value, final boolean transitional) {
    super();
    this.value = value;
    this.transitional = transitional;
  }

  public boolean isTransitional() {
    return transitional;
  }

  public void setTransitional(final boolean transitional) {
    this.transitional = transitional;
  }

  public CertificateCredentialValue getValue() {
    return value;
  }

  public void setValue(final CertificateCredentialValue value) {
    this.value = value;
  }
}
