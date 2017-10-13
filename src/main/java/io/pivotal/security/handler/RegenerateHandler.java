package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.BulkRegenerateResults;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;

@Service
public class RegenerateHandler {

  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;

  RegenerateHandler(
      PermissionedCredentialService credentialService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator) {
    this.credentialService = credentialService;
    this.credentialService = credentialService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
  }

  public CredentialView handleRegenerate(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator.createGenerateRequest(existingCredentialVersion, credentialName, auditRecordParameters);
    CredentialValue credentialValue = credentialGenerator.generate(generateRequest);

    final CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion,
        generateRequest.getName(),
        generateRequest.getType(),
        credentialValue,
        generateRequest.getGenerationParameters(),
        generateRequest.getAdditionalPermissions(),
        generateRequest.getOverwriteMode(),
        auditRecordParameters
    );

    return CredentialView.fromEntity(credentialVersion);
  }

  public BulkRegenerateResults handleBulkRegenerate(
      String signerName,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    BulkRegenerateResults results = new BulkRegenerateResults();
    List<String> certificateNames = credentialService.findAllCertificateCredentialsByCaName(
        signerName);

    final HashSet<String> credentialNamesSet = new HashSet<>(certificateNames);
    for (String name : credentialNamesSet) {
      this.handleRegenerate(name,
          auditRecordParameters);
    }

    results.setRegeneratedCredentials(credentialNamesSet);
    return results;
  }
}
