package io.pivotal.security.service.regeneratables;

import static org.apache.commons.lang3.StringUtils.isEmpty;

import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.util.CertificateReader;
import org.springframework.http.ResponseEntity;

public class CertificateSecret implements Regeneratable {

  private GenerateService generateService;

  public CertificateSecret(GenerateService generateService) {
    this.generateService = generateService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    NamedCertificateSecret certificateSecret = (NamedCertificateSecret) secret;
    CertificateReader reader = new CertificateReader(certificateSecret.getCertificate());

    if (!reader.isValid() || (isEmpty(certificateSecret.getCaName()) && !reader.isSelfSigned())) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_certificate");
    }

    CertificateParameters certificateParameters = new CertificateParameters(reader,
        certificateSecret.getCaName());

    CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateSecret.getName());
    generateRequest.setType(certificateSecret.getSecretType());
    generateRequest.setCertificateParameters(certificateParameters);
    return generateService.performGenerate(auditRecordBuilder, generateRequest);
  }
}
