package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.service.CertificateService;
import org.cloudfoundry.credhub.service.PermissionedCertificateService;
import org.cloudfoundry.credhub.view.CertificateCredentialView;
import org.cloudfoundry.credhub.view.CertificateCredentialsView;
import org.cloudfoundry.credhub.view.CertificateView;
import org.cloudfoundry.credhub.view.CredentialView;
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
      String credentialUuid,
      List<EventAuditRecordParameters> auditRecordParameters,
      CertificateRegenerateRequest request) {

    CertificateCredentialVersion existingCredentialVersion = certificateService
        .findByCredentialUuid(credentialUuid, auditRecordParameters);

    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator
        .createGenerateRequest(existingCredentialVersion, existingCredentialVersion.getName(), auditRecordParameters);
    CertificateCredentialValue credentialValue = (CertificateCredentialValue) credentialGenerator.generate(generateRequest);
    credentialValue.setTransitional(request.isTransitional());

    final CertificateCredentialVersion credentialVersion = (CertificateCredentialVersion) permissionedCertificateService.save(
        existingCredentialVersion,
        credentialValue,
        generateRequest,
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

  public CertificateCredentialsView handleGetByNameRequest(String name, List<EventAuditRecordParameters> auditRecordParameters) {
    final List<Credential> credentialList = permissionedCertificateService.getByName(name, auditRecordParameters);

    List<CertificateCredentialView> list = credentialList.stream().map(credential ->
        new CertificateCredentialView(credential.getName(), credential.getUuid())
    ).collect(Collectors.toList());

    return new CertificateCredentialsView(list);
  }
}
