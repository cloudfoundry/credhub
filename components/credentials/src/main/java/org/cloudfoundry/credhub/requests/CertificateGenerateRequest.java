package org.cloudfoundry.credhub.requests;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

public class CertificateGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private CertificateGenerationRequestParameters requestGenerationParameters;

  @JsonIgnore
  private CertificateGenerationParameters certificateGenerationParameters;

  public CertificateGenerationRequestParameters getGenerationRequestParameters() {
    if (requestGenerationParameters == null) {
      requestGenerationParameters = new CertificateGenerationRequestParameters();
    }
    return requestGenerationParameters;
  }

  @SuppressWarnings("unused")
  public void setRequestGenerationParameters(final CertificateGenerationRequestParameters requestGenerationParameters) {
    this.requestGenerationParameters = requestGenerationParameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
    if (certificateGenerationParameters == null && requestGenerationParameters == null) {
      throw new ParameterizedValidationException(ErrorMessages.NO_CERTIFICATE_PARAMETERS);
    }

    if (certificateGenerationParameters == null) {
      certificateGenerationParameters = new CertificateGenerationParameters(requestGenerationParameters);
    }
    return certificateGenerationParameters;
  }

  @Override
  public void validate() {
    super.validate();
    getGenerationRequestParameters().validate();
  }

  public void setCertificateGenerationParameters(final CertificateGenerationParameters certificateGenerationParameters) {
    this.certificateGenerationParameters = certificateGenerationParameters;
  }
}
