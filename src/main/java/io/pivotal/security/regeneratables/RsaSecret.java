package io.pivotal.security.regeneratables;

import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.request.RsaGenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import org.springframework.http.ResponseEntity;

public class RsaSecret implements Regeneratable {
  private GenerateService generateService;

  public RsaSecret(ErrorResponseService responseService, GenerateService generateService) {
    this.generateService = generateService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    NamedRsaSecret rsaSecret = (NamedRsaSecret) secret;
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaSecret.getName());
    generateRequest.setType(rsaSecret.getSecretType());

    return generateService.performGenerate(auditRecordBuilder, generateRequest);
  }
}
