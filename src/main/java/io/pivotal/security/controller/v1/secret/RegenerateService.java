package io.pivotal.security.controller.v1.secret;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.regeneratables.NotRegeneratable;
import io.pivotal.security.regeneratables.PasswordSecret;
import io.pivotal.security.regeneratables.Regeneratable;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import java.util.HashMap;
import java.util.Map;
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
    this.regeneratableTypes
        .put("password", new PasswordSecret(errorResponseService, generateService));
  }

  public ResponseEntity performRegenerate(AuditRecordBuilder auditRecordBuilder,
      SecretRegenerateRequest requestBody) {
    constructGeneratorMap();

    NamedSecret secret = secretDataService.findMostRecent(requestBody.getName());
    if (secret == null) {
      return null;
    }

    return regeneratableTypes.getOrDefault(secret.getSecretType(), new NotRegeneratable())
        .regenerate(secret, auditRecordBuilder);
  }
}
