package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.CertificateRegenerateRequest;
import io.pivotal.security.service.CertificateService;
import io.pivotal.security.service.PermissionedCertificateService;
import io.pivotal.security.view.CertificateCredentialView;
import io.pivotal.security.view.CertificateCredentialsView;
import io.pivotal.security.view.CertificateView;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CertificatesHandler {

  private PermissionedCertificateService permissionedCertificateService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private CertificateService certificateService;

  CertificatesHandler(
      PermissionedCertificateService permissionedCertificateService,
      CertificateService certificateService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator) {
    this.permissionedCertificateService = permissionedCertificateService;
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

    final CertificateCredentialVersion credentialVersion = (CertificateCredentialVersion) permissionedCertificateService.save(
        existingCredentialVersion,
        generateRequest.getName(),
        credentialValue,
        generateRequest.getGenerationParameters(),
        generateRequest.getAdditionalPermissions(),
        generateRequest.getOverwriteMode(),
        auditRecordParameters
    );

    return new CertificateView(credentialVersion);
  }

  public CertificateCredentialsView handleGetAllRequest(List<EventAuditRecordParameters> auditRecordParameters) {
    final List<Credential> credentialList = permissionedCertificateService.getAll(auditRecordParameters);

    List<CertificateCredentialView> list = credentialList.stream().map(credential ->
        new CertificateCredentialView(credential.getName(), credential.getUuid())
    ).collect(Collectors.toList());

    return new CertificateCredentialsView(list);
  }
}
