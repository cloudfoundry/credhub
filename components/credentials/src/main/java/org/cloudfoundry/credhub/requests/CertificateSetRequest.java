package org.cloudfoundry.credhub.requests;


import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;

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
    final CertificateCredentialValue certificateValue) {
    this.certificateValue = certificateValue;
  }

  @Override
  public CertificateCredentialValue getCredentialValue() {
    return certificateValue;
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
