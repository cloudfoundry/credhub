package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.service.CredentialService;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.BulkRegenerateResults;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class RegenerateHandler {

  private CredentialDataService credentialDataService;
  private CredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private final PermissionService permissionService;
  private GenerationRequestGenerator generationRequestGenerator;

  RegenerateHandler(
      CredentialDataService credentialDataService,
      CredentialService credentialService,
      PermissionService permissionService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator) {
    this.credentialDataService = credentialDataService;
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
    Credential credential = credentialDataService.findMostRecent(credentialName);
    if (credential == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (credential instanceof PasswordCredential && ((PasswordCredential) credential).getGenerationParameters() == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
    }

    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator.createGenerateRequest(credential);
    CredentialValue credentialValue = credentialGenerator.generate(generateRequest, userContext);

    StringGenerationParameters generationParameters = null;
    if (generateRequest instanceof PasswordGenerateRequest) {
      generationParameters = (StringGenerationParameters) generateRequest.getGenerationParameters();
    }
    if (generateRequest instanceof UserGenerateRequest) {
      generationParameters = ((UserGenerateRequest) generateRequest).getUserCredentialGenerationParameters();
    }

    return credentialService.save(
        generateRequest.getName(),
        generateRequest.getType(),
        credentialValue,
        generationParameters,
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
    if (!permissionService.hasPermission(userContext.getAclUser(), signerName, PermissionOperation.READ)) {
      throw new PermissionException("error.credential.invalid_access");
    }

    BulkRegenerateResults results = new BulkRegenerateResults();
    List<String> certificateNames = credentialDataService.findAllCertificateCredentialsByCaName(signerName);

    final HashSet<String> credentialNamesSet = new HashSet<>(certificateNames);
    for (String name : credentialNamesSet) {
      this.handleRegenerate(name, userContext, currentUserPermissionEntry,
          auditRecordParameters);
    }

    results.setRegeneratedCredentials(credentialNamesSet);
    return results;
  }
}
