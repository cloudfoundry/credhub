package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.BulkRegenerateCredential;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CertificateGenerateRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.BulkRegenerateResults;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.TreeSet;

@Service
public class RegenerateHandler {

  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private CEFAuditRecord auditRecord;

  RegenerateHandler(
      PermissionedCredentialService credentialService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator,
      CEFAuditRecord auditRecord) {
    this.credentialService = credentialService;
    this.credentialService = credentialService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
    this.auditRecord = auditRecord;
  }

  public CredentialView handleRegenerate(String credentialName) {
    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator
        .createGenerateRequest(existingCredentialVersion);
    CredentialValue credentialValue = credentialGenerator.generate(generateRequest);

    final CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion,
        credentialValue,
        generateRequest
    );

    auditRecord.setResource(credentialVersion);
    return CredentialView.fromEntity(credentialVersion);
  }

  public BulkRegenerateResults handleBulkRegenerate(String signerName) {
    auditRecord.setRequestDetails(new BulkRegenerateCredential(signerName));

    BulkRegenerateResults results = new BulkRegenerateResults();
    TreeSet<String> certificateSet = new TreeSet(String.CASE_INSENSITIVE_ORDER);

    certificateSet.addAll(regenerateCertificatesSignedByCA(signerName));
    results.setRegeneratedCredentials(certificateSet);
    return results;
  }

  private TreeSet<String> regenerateCertificatesSignedByCA(String signerName) {
    TreeSet<String> results = new TreeSet(String.CASE_INSENSITIVE_ORDER);
    TreeSet<String> certificateNames = new TreeSet(String.CASE_INSENSITIVE_ORDER);

    certificateNames.addAll(credentialService.findAllCertificateCredentialsByCaName(signerName));
    certificateNames.stream().map(name -> this.regenerateCertificateAndDirectChildren(name))
        .forEach(results::addAll);

    return results;
  }

  private TreeSet<String> regenerateCertificateAndDirectChildren(String credentialName) {
    TreeSet<String> results = new TreeSet(String.CASE_INSENSITIVE_ORDER);
    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    CertificateGenerateRequest generateRequest = (CertificateGenerateRequest) generationRequestGenerator
        .createGenerateRequest(existingCredentialVersion);
    CredentialValue newCredentialValue = credentialGenerator.generate(generateRequest);

    auditRecord.addResource(existingCredentialVersion);

    CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion,
        newCredentialValue,
        generateRequest
    );
    results.add(credentialVersion.getName());

    CertificateGenerationParameters generationParameters = (CertificateGenerationParameters) generateRequest
        .getGenerationParameters();
    if (generationParameters.isCa()) {
      results.addAll(this.regenerateCertificatesSignedByCA(generateRequest.getName()));
    }
    return results;
  }
}
