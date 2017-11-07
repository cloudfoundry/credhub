package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.CertificateRegenerateRequest;
import io.pivotal.security.service.CertificateService;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.CertificateView;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CertificatesHandler {

  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private CertificateService certificateService;

  CertificatesHandler(
      PermissionedCredentialService credentialService,
      CertificateService certificateService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator) {
    this.credentialService = credentialService;
    this.certificateService = certificateService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
  }

  public CredentialView handleRegenerate(
      String certificateId,
      List<EventAuditRecordParameters> auditRecordParameters,
      CertificateRegenerateRequest request) {
    CertificateCredentialVersion existingCredentialVersion = certificateService
        .findByUuid(certificateId, auditRecordParameters);

    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator
        .createGenerateRequest(existingCredentialVersion, existingCredentialVersion.getName(), auditRecordParameters);
    CertificateCredentialValue credentialValue = (CertificateCredentialValue) credentialGenerator.generate(generateRequest);
    credentialValue.setTransitional(request.isTransitional());

    final CertificateCredentialVersion credentialVersion = (CertificateCredentialVersion) credentialService.save(
        existingCredentialVersion,
        generateRequest.getName(),
        generateRequest.getType(),
        credentialValue,
        generateRequest.getGenerationParameters(),
        generateRequest.getAdditionalPermissions(),
        generateRequest.getOverwriteMode(),
        auditRecordParameters
    );

    return new CertificateView(credentialVersion, credentialValue);
  }
}
