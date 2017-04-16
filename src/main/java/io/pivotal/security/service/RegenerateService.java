package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordBuilder;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.regeneratables.*;
import io.pivotal.security.view.SecretView;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class RegenerateService {

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

  public SecretView performRegenerate(
      EventAuditRecordBuilder auditRecordBuilder,
      SecretRegenerateRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry) {
    NamedSecret secret = secretDataService.findMostRecent(requestBody.getName());
    auditRecordBuilder.setAuditingOperationCode(CREDENTIAL_UPDATE);
    if (secret == null) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    Regeneratable regeneratable = regeneratableTypes
        .getOrDefault(secret.getSecretType(), NotRegeneratable::new)
        .get();

    return generateService
        .performGenerate(auditRecordBuilder, regeneratable.createGenerateRequest(secret), currentUserAccessControlEntry);
  }
}
