package org.cloudfoundry.credhub.handler;

import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.BulkRegenerateCredential;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CertificateGenerateRequest;
import org.cloudfoundry.credhub.service.DefaultPermissionedCredentialService;
import org.cloudfoundry.credhub.view.BulkRegenerateResults;
import org.cloudfoundry.credhub.view.CredentialView;

@Service
public class DefaultRegenerateHandler implements RegenerateHandler {

  private final PermissionedCredentialService credentialService;
  private final UniversalCredentialGenerator credentialGenerator;
  private final GenerationRequestGenerator generationRequestGenerator;
  private final CEFAuditRecord auditRecord;

  DefaultRegenerateHandler(
    final PermissionedCredentialService credentialService,
    final UniversalCredentialGenerator credentialGenerator,
    final GenerationRequestGenerator generationRequestGenerator,
    final CEFAuditRecord auditRecord
  ) {
    super();
    this.credentialService = credentialService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
    this.auditRecord = auditRecord;
  }

  @Override
  public CredentialView handleRegenerate(final String credentialName) {
    final CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    final BaseCredentialGenerateRequest generateRequest = generationRequestGenerator
      .createGenerateRequest(existingCredentialVersion);
    final CredentialValue credentialValue = credentialGenerator.generate(generateRequest);

    final CredentialVersion credentialVersion = credentialService.save(
      existingCredentialVersion,
      credentialValue,
      generateRequest
    );

    auditRecord.setVersion(credentialVersion);
    auditRecord.setResource(credentialVersion.getCredential());
    return CredentialView.fromEntity(credentialVersion);
  }

  @Override
  public BulkRegenerateResults handleBulkRegenerate(final String signerName) {
    auditRecord.setRequestDetails(new BulkRegenerateCredential(signerName));

    final BulkRegenerateResults results = new BulkRegenerateResults();
    final Set<String> certificateSet = new TreeSet(String.CASE_INSENSITIVE_ORDER);

    certificateSet.addAll(regenerateCertificatesSignedByCA(signerName));
    results.setRegeneratedCredentials(certificateSet);
    return results;
  }

  private Collection<String> regenerateCertificatesSignedByCA(final String signerName) {
    final Set<String> results = new TreeSet(String.CASE_INSENSITIVE_ORDER);
    final Set<String> certificateNames = new TreeSet(String.CASE_INSENSITIVE_ORDER);

    certificateNames.addAll(credentialService.findAllCertificateCredentialsByCaName(signerName));
    certificateNames.stream().map(name -> this.regenerateCertificateAndDirectChildren(name))
      .forEach(results::addAll);

    return results;
  }

  private Set<String> regenerateCertificateAndDirectChildren(final String credentialName) {
    final Set<String> results = new TreeSet(String.CASE_INSENSITIVE_ORDER);
    final CredentialVersion existingCredentialVersion = credentialService.findMostRecent(credentialName);
    final CertificateGenerateRequest generateRequest = (CertificateGenerateRequest) generationRequestGenerator
      .createGenerateRequest(existingCredentialVersion);
    final CredentialValue newCredentialValue = credentialGenerator.generate(generateRequest);

    auditRecord.addVersion(existingCredentialVersion);
    auditRecord.addResource(existingCredentialVersion.getCredential());

    final CredentialVersion credentialVersion = credentialService.save(
      existingCredentialVersion,
      newCredentialValue,
      generateRequest
    );
    results.add(credentialVersion.getName());

    final CertificateGenerationParameters generationParameters = (CertificateGenerationParameters) generateRequest
      .getGenerationParameters();
    if (generationParameters.isCa()) {
      results.addAll(this.regenerateCertificatesSignedByCA(generateRequest.getName()));
    }
    return results;
  }
}
