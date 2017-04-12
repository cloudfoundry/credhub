package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.service.GeneratorService;

public class CertificateGenerateRequest extends BaseSecretGenerateRequest {

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

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    CertificateSetRequest certificateSetRequest = new CertificateSetRequest();
    String caName= null;
    if (certificateParameters == null) {
       certificateParameters = new CertificateParameters(getGenerationParameters());
       caName = certificateParameters.getCaName();
    }
    Certificate certificate = generatorService.generateCertificate(certificateParameters);
    certificateSetRequest.setName(getName());
    certificateSetRequest.setType(getType());
    certificateSetRequest.setOverwrite(isOverwrite());

    CertificateSetRequestFields certificateSetRequestFields = new CertificateSetRequestFields(
        certificate.getPrivateKey(),
        certificate.getPublicKeyCertificate(),
        certificate.getCaCertificate(),
        caName);

    certificateSetRequest.setCertificateFields(certificateSetRequestFields);

    return certificateSetRequest;
  }

  public void setCertificateParameters(
      CertificateParameters certificateParameters) {
    this.certificateParameters = certificateParameters;
  }

  public CertificateParameters getCertParameters() {
    return certificateParameters;
  }
}
