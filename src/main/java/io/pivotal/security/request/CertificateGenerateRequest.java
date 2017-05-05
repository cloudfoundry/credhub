package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.service.GeneratorService;

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

  public BaseCredentialSetRequest generateSetRequest(GeneratorService generatorService) {
    CertificateSetRequest certificateSetRequest = new CertificateSetRequest();
    if (certificateParameters == null) {
       certificateParameters = new CertificateParameters(getGenerationParameters());
    }
    CertificateCredentialValue certificate = generatorService.generateCertificate(certificateParameters);
    certificateSetRequest.setName(getName());
    certificateSetRequest.setType(getType());
    certificateSetRequest.setOverwrite(isOverwrite());
    certificateSetRequest.setCertificateValue(certificate);
    certificateSetRequest.setAccessControlEntries(getAccessControlEntries());

    return certificateSetRequest;
  }

  public void setCertificateParameters(
      CertificateParameters certificateParameters) {
    this.certificateParameters = certificateParameters;
  }
}
