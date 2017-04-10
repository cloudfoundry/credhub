package io.pivotal.security.controller.v1.secret;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.regeneratables.CertificateSecret;
import io.pivotal.security.service.regeneratables.NotRegeneratable;
import io.pivotal.security.service.regeneratables.PasswordSecret;
import io.pivotal.security.service.regeneratables.Regeneratable;
import io.pivotal.security.service.regeneratables.RsaSecret;
import io.pivotal.security.service.regeneratables.SshSecret;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
class RegenerateService {

  private SecretDataService secretDataService;
  private GenerateService generateService;
  private Map<String, Regeneratable> regeneratableTypes;

  RegenerateService(
      SecretDataService secretDataService,
      GenerateService generateService
  ) {
    this.secretDataService = secretDataService;
    this.generateService = generateService;
  }

  private void constructGeneratorMap() {
    this.regeneratableTypes = new HashMap<>();
    this.regeneratableTypes.put("password", new PasswordSecret(generateService));
    this.regeneratableTypes.put("ssh", new SshSecret(generateService));
    this.regeneratableTypes.put("rsa", new RsaSecret(generateService));
    this.regeneratableTypes.put("certificate", new CertificateSecret(generateService));
  }

  public ResponseEntity performRegenerate(AuditRecordBuilder auditRecordBuilder,
      SecretRegenerateRequest requestBody) {
    constructGeneratorMap();

    NamedSecret secret = secretDataService.findMostRecent(requestBody.getName());
    if (secret == null) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    return regeneratableTypes.getOrDefault(secret.getSecretType(),
        new NotRegeneratable())
        .regenerate(secret, auditRecordBuilder);
  }
}
