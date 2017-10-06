package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.BulkRegenerateResults;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class RegenerateHandler {

  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private final PermissionService permissionService;
  private GenerationRequestGenerator generationRequestGenerator;

  RegenerateHandler(
      PermissionedCredentialService credentialService,
      PermissionService permissionService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator) {
    this.credentialService = credentialService;
    this.permissionService = permissionService;
    this.credentialService = credentialService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
  }

  public CredentialView handleRegenerate(
      String credentialName,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    if (existingCredentialVersion == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (existingCredentialVersion instanceof PasswordCredentialVersion && ((PasswordCredentialVersion) existingCredentialVersion).getGenerationParameters() == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
    }

    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator.createGenerateRequest(existingCredentialVersion);
    CredentialValue credentialValue = credentialGenerator.generate(generateRequest, userContext);

    return credentialService.save(
        generateRequest.getName(),
        generateRequest.getType(),
        credentialValue,
        generateRequest.getGenerationParameters(),
        generateRequest.getAdditionalPermissions(),
        generateRequest.isOverwrite(),
        userContext,
        currentUserPermissionEntry,
        auditRecordParameters
    );
  }

  public BulkRegenerateResults handleBulkRegenerate(
      String signerName,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    BulkRegenerateResults results = new BulkRegenerateResults();
    List<String> certificateNames = credentialService.findAllCertificateCredentialsByCaName(userContext, signerName);

    final HashSet<String> credentialNamesSet = new HashSet<>(certificateNames);
    for (String name : credentialNamesSet) {
      this.handleRegenerate(name, userContext, currentUserPermissionEntry,
          auditRecordParameters);
    }

    results.setRegeneratedCredentials(credentialNamesSet);
    return results;
  }
}
