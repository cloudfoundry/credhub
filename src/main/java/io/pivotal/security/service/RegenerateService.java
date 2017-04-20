package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.service.regeneratables.*;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class RegenerateService {

  private CredentialDataService credentialDataService;
  private GenerateService generateService;
  private Map<String, Supplier<Regeneratable>> regeneratableTypes;

  RegenerateService(
      CredentialDataService credentialDataService,
      GenerateService generateService
  ) {
    this.credentialDataService = credentialDataService;
    this.generateService = generateService;

    this.regeneratableTypes = new HashMap<>();
    this.regeneratableTypes.put("password", PasswordCredentialRegeneratable::new);
    this.regeneratableTypes.put("ssh", SshCredentialRegeneratable::new);
    this.regeneratableTypes.put("rsa", RsaCredentialRegeneratable::new);
    this.regeneratableTypes.put("certificate", CertificateCredentialRegeneratable::new);
  }

  public CredentialView performRegenerate(
      EventAuditRecordParameters eventAuditRecordParameters,
      CredentialRegenerateRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry) {
    Credential secret = credentialDataService.findMostRecent(requestBody.getName());
    eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_UPDATE);
    if (secret == null) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    Regeneratable regeneratable = regeneratableTypes
        .getOrDefault(secret.getSecretType(), NotRegeneratable::new)
        .get();

    return generateService
        .performGenerate(eventAuditRecordParameters, regeneratable.createGenerateRequest(secret), currentUserAccessControlEntry);
  }
}
