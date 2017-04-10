package io.pivotal.security.controller.v1.secret;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.regeneratables.CertificateSecretRegeneratable;
import io.pivotal.security.service.regeneratables.NotRegeneratable;
import io.pivotal.security.service.regeneratables.PasswordSecretRegeneratable;
import io.pivotal.security.service.regeneratables.Regeneratable;
import io.pivotal.security.service.regeneratables.RsaSecretRegeneratable;
import io.pivotal.security.service.regeneratables.SshSecretRegeneratable;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
class RegenerateService {

  private SecretDataService secretDataService;
  private GenerateService generateService;
  private Map<String, Supplier<Regeneratable>> regeneratableTypes;

  RegenerateService(
      SecretDataService secretDataService,
      GenerateService generateService
  ) {
    this.secretDataService = secretDataService;
    this.generateService = generateService;

    this.regeneratableTypes = new HashMap<>();
    this.regeneratableTypes.put("password", PasswordSecretRegeneratable::new);
    this.regeneratableTypes.put("ssh", SshSecretRegeneratable::new);
    this.regeneratableTypes.put("rsa", RsaSecretRegeneratable::new);
    this.regeneratableTypes.put("certificate", CertificateSecretRegeneratable::new);
  }

  public ResponseEntity performRegenerate(AuditRecordBuilder auditRecordBuilder,
      SecretRegenerateRequest requestBody) {
    NamedSecret secret = secretDataService.findMostRecent(requestBody.getName());
    if (secret == null) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    Regeneratable regeneratable = regeneratableTypes
        .getOrDefault(secret.getSecretType(), NotRegeneratable::new)
        .get();

    return generateService
        .performGenerate(auditRecordBuilder, regeneratable.createGenerateRequest(secret));
  }
}
