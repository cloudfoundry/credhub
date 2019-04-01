package org.cloudfoundry.credhub.requests;


import java.util.Objects;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;

@SuppressWarnings("unused")
public class CertificateSetRequest extends BaseCredentialSetRequest<CertificateCredentialValue> {

  @NotNull(message = ErrorMessages.MISSING_VALUE)
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

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final CertificateSetRequest that = (CertificateSetRequest) o;
    return Objects.equals(certificateValue, that.certificateValue);
  }

  @Override
  public int hashCode() {
    return Objects.hash(certificateValue);
  }
}
