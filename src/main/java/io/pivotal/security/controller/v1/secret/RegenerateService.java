package io.pivotal.security.controller.v1.secret;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.regeneratables.CertificateSecret;
import io.pivotal.security.service.regeneratables.NotRegeneratable;
import io.pivotal.security.service.regeneratables.PasswordSecret;
import io.pivotal.security.service.regeneratables.Regeneratable;
import io.pivotal.security.service.regeneratables.RsaSecret;
import io.pivotal.security.service.regeneratables.SshSecret;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
class RegenerateService {

  private ErrorResponseService errorResponseService;
  private SecretDataService secretDataService;
  private GenerateService generateService;
  private Map<String, Regeneratable> regeneratableTypes;

  RegenerateService(
      ErrorResponseService errorResponseService,
      SecretDataService secretDataService,
      GenerateService generateService
  ) {
    this.errorResponseService = errorResponseService;
    this.secretDataService = secretDataService;
    this.generateService = generateService;
  }

  private void constructGeneratorMap() {
    this.regeneratableTypes = new HashMap<>();
    this.regeneratableTypes.put("password", new PasswordSecret(errorResponseService, generateService));
    this.regeneratableTypes.put("ssh", new SshSecret(errorResponseService, generateService));
    this.regeneratableTypes.put("rsa", new RsaSecret(errorResponseService, generateService));
    this.regeneratableTypes.put("certificate", new CertificateSecret(errorResponseService, generateService));
  }

  public ResponseEntity performRegenerate(AuditRecordBuilder auditRecordBuilder,
      SecretRegenerateRequest requestBody) {
    constructGeneratorMap();

    NamedSecret secret = secretDataService.findMostRecent(requestBody.getName());
    if (secret == null) {
      return new ResponseEntity<>(errorResponseService.createErrorResponse("error.credential_not_found"), HttpStatus.BAD_REQUEST);
    }

    return regeneratableTypes.getOrDefault(secret.getSecretType(),
        new NotRegeneratable(errorResponseService))
        .regenerate(secret, auditRecordBuilder);
  }
}
