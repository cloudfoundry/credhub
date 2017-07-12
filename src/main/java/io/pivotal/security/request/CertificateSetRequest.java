package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.CertificateCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

@SuppressWarnings("unused")
public class CertificateSetRequest extends BaseCredentialSetRequest<CertificateCredentialValue> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private CertificateCredentialValue certificateValue;

  public CertificateCredentialValue getCertificateValue() {
    return certificateValue;
  }

  public void setCertificateValue(
      CertificateCredentialValue certificateValue) {
    this.certificateValue = certificateValue;
  }

  @Override
  public CertificateCredentialValue getCredentialValue() {
    return certificateValue;
  }
}
