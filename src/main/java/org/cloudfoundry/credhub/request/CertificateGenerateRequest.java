package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;

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
  public void setRequestGenerationParameters(CertificateGenerationRequestParameters requestGenerationParameters) {
    this.requestGenerationParameters = requestGenerationParameters;
  }

  @Override
  @JsonIgnore
  public GenerationParameters getGenerationParameters() {
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

  public void setCertificateGenerationParameters(CertificateGenerationParameters certificateGenerationParameters) {
    this.certificateGenerationParameters = certificateGenerationParameters;
  }
}
