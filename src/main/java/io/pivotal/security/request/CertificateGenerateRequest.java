package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.CertificateParameters;

public class CertificateGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private CertificateGenerationParameters generationParameters;

  @JsonIgnore
  private CertificateParameters certificateParameters;

  public CertificateGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new CertificateGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(CertificateGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  public CertificateParameters getCertificateParameters() {
    return certificateParameters;
  }

  public void setCertificateParameters(
      CertificateParameters certificateParameters) {
    this.certificateParameters = certificateParameters;
  }
}
