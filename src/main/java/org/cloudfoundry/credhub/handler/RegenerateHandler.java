package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CertificateGenerateRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.BulkRegenerateResults;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@SuppressWarnings("unchecked")
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
    TreeSet<String> certificateSet =  new TreeSet(String.CASE_INSENSITIVE_ORDER);

    certificateSet.addAll(regenerateCertificatesSignedByCA(signerName, auditRecordParameters));
    results.setRegeneratedCredentials(certificateSet);
    return results;
  }

  private TreeSet<String> regenerateCertificatesSignedByCA(
      String signerName,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    TreeSet<String> results =  new TreeSet(String.CASE_INSENSITIVE_ORDER);
    TreeSet<String> certificateNames =  new TreeSet(String.CASE_INSENSITIVE_ORDER);

    certificateNames.addAll(credentialService.findAllCertificateCredentialsByCaName(signerName));
    certificateNames.stream().map(name -> this.regenerateCertificateAndDirectChildren(name, auditRecordParameters)).forEach(results::addAll);

    return results;
  }

  private TreeSet<String> regenerateCertificateAndDirectChildren(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    TreeSet<String> results = new TreeSet(String.CASE_INSENSITIVE_ORDER);
    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    CertificateGenerateRequest generateRequest = (CertificateGenerateRequest)generationRequestGenerator.createGenerateRequest(existingCredentialVersion, credentialName, auditRecordParameters);
    CredentialValue newCredentialValue = credentialGenerator.generate(generateRequest);

    CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion,
        newCredentialValue,
        generateRequest,
        auditRecordParameters
    );
    results.add(credentialVersion.getName());

    CertificateGenerationParameters generationParameters = (CertificateGenerationParameters)generateRequest.getGenerationParameters();
    if (generationParameters.isCa()) {
      results.addAll(this.regenerateCertificatesSignedByCA(generateRequest.getName(), auditRecordParameters));
    }
    return results;
  }
}
