package io.pivotal.security.service.regeneratables;

import static org.apache.commons.lang3.StringUtils.isEmpty;

import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.util.CertificateReader;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class CertificateSecret implements Regeneratable {

  private ErrorResponseService errorResponseService;
  private GenerateService generateService;

  public CertificateSecret(ErrorResponseService responseService, GenerateService generateService) {
    errorResponseService = responseService;
    this.generateService = generateService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    NamedCertificateSecret certificateSecret = (NamedCertificateSecret) secret;
    CertificateReader reader = new CertificateReader(certificateSecret.getCertificate());

    if (!reader.isValid() || (isEmpty(certificateSecret.getCaName()) && !reader.isSelfSigned())) {
      return new ResponseEntity<>(errorResponseService.createErrorResponse("error.cannot_regenerate_non_generated_certificate"), HttpStatus.BAD_REQUEST);
    }

    CertificateParameters certificateParameters = new CertificateParameters(reader, certificateSecret.getCaName());

    CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateSecret.getName());
    generateRequest.setType(certificateSecret.getSecretType());
    generateRequest.setCertificateParameters(certificateParameters);
    return generateService.performGenerate(auditRecordBuilder, generateRequest);
  }
}
