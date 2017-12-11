package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.BulkRegenerateResults;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.LinkedHashSet;
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
        credentialValue,
        generateRequest,
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

    certificateNames.sort(String::compareToIgnoreCase);

    final HashSet<String> credentialNamesSet = new LinkedHashSet<>(certificateNames);
    for (String name : credentialNamesSet) {
      this.handleRegenerate(name,
          auditRecordParameters);
    }

    results.setRegeneratedCredentials(credentialNamesSet);
    return results;
  }
}
