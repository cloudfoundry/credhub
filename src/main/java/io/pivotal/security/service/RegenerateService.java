package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.CredentialValueFactory;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.service.regeneratables.CertificateCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.NotRegeneratable;
import io.pivotal.security.service.regeneratables.PasswordCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.Regeneratable;
import io.pivotal.security.service.regeneratables.RsaCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.SshCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.UserCredentialRegeneratable;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class RegenerateService {

  private CredentialDataService credentialDataService;
  private Map<String, Supplier<Regeneratable>> regeneratableTypes;
  private CredentialService credentialService;
  private GeneratorService generatorService;

  RegenerateService(
      CredentialDataService credentialDataService,
      CredentialService credentialService,
      GeneratorService generatorService) {
    this.credentialDataService = credentialDataService;
    this.credentialService = credentialService;
    this.generatorService = generatorService;

    this.regeneratableTypes = new HashMap<>();
    this.regeneratableTypes.put("password", PasswordCredentialRegeneratable::new);
    this.regeneratableTypes.put("user", UserCredentialRegeneratable::new);
    this.regeneratableTypes.put("ssh", SshCredentialRegeneratable::new);
    this.regeneratableTypes.put("rsa", RsaCredentialRegeneratable::new);
    this.regeneratableTypes.put("certificate", CertificateCredentialRegeneratable::new);
  }

  public CredentialView performRegenerate(
      String credentialName,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    Credential credential = credentialDataService.findMostRecent(credentialName);
    if (credential == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    Regeneratable regeneratable = regeneratableTypes
        .getOrDefault(credential.getCredentialType(), NotRegeneratable::new)
        .get();

    if (credential instanceof PasswordCredential && ((PasswordCredential) credential).getGenerationParameters() == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
    }

    final BaseCredentialGenerateRequest generateRequest = regeneratable
        .createGenerateRequest(credential);

    final CredentialValue credentialValue = CredentialValueFactory
        .generateValue(generateRequest, generatorService);

    StringGenerationParameters generationParameters = null;
    if (generateRequest instanceof PasswordGenerateRequest) {
      generationParameters = ((PasswordGenerateRequest) generateRequest).getGenerationParameters();
    }
    if (generateRequest instanceof UserGenerateRequest) {
      generationParameters = ((UserGenerateRequest) generateRequest).getPasswordGenerationParameters();
    }

    return credentialService.save(
        userContext,
        auditRecordParameters,
        generateRequest.getName(),
        generateRequest.isOverwrite(),
        generateRequest.getType(),
        generationParameters,
        credentialValue,
        generateRequest.getAdditionalPermissions(),
        currentUserPermissionEntry);
  }
}
